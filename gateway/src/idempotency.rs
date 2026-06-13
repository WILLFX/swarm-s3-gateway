use anyhow::{Context, Result};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};
use tracing::warn;

use crate::s3_response::{S3ErrorKind, S3ErrorResponse};

pub const IDEMPOTENCY_KEY_HEADER: &str = "x-s3gw-idempotency-key";
pub const IDEMPOTENCY_JOURNAL_PATH_ENV: &str = "S3GW_IDEMPOTENCY_JOURNAL_PATH";

const JOURNAL_RECORD_VERSION: u32 = 1;

#[derive(Debug)]
pub struct GatewayIdempotencyStore {
    path: PathBuf,
    state: Mutex<IdempotencyState>,
}

#[derive(Debug, Default)]
struct IdempotencyState {
    entries: HashMap<String, IdempotencyEntry>,
    next_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdempotencyEntry {
    Pending {
        request_digest_hex: String,
    },
    Succeeded {
        request_digest_hex: String,
        response: StoredIdempotencyResponse,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredIdempotencyResponse {
    pub status: u16,
    pub headers: Vec<StoredHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_body: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IdempotencyJournalRecord {
    version: u32,
    event_id: String,
    recorded_at_unix_ms: u64,
    event: IdempotencyJournalEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
enum IdempotencyJournalEvent {
    Started {
        idempotency_key_hex: String,
        request_digest_hex: String,
    },
    Succeeded {
        idempotency_key_hex: String,
        request_digest_hex: String,
        response: StoredIdempotencyResponse,
    },
    Failed {
        idempotency_key_hex: String,
        request_digest_hex: String,
        error: String,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdempotencyError {
    #[error("idempotency key is required to be a 32-byte random hex value")]
    InvalidKey,
    #[error("idempotency key was supplied but gateway idempotency store is not configured")]
    StoreNotConfigured,
    #[error("gateway idempotency store is unavailable: {0}")]
    StoreUnavailable(String),
    #[error("idempotency key is already in progress")]
    InProgress,
    #[error("idempotency key was already used with a different request digest")]
    Conflict,
}

#[derive(Debug)]
pub enum IdempotencyDecision {
    Fresh(IdempotencyReservation),
    Replay(StoredIdempotencyResponse),
}

#[derive(Debug)]
pub struct IdempotencyReservation {
    store: Arc<GatewayIdempotencyStore>,
    idempotency_key_hex: String,
    request_digest_hex: String,
}

impl GatewayIdempotencyStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let entries = replay_records(Self::load_records(&path)?)?;

        Ok(Self {
            path,
            state: Mutex::new(IdempotencyState {
                entries,
                next_sequence: 1,
            }),
        })
    }

    pub fn from_env() -> Result<Option<Arc<Self>>> {
        let Some(path) = env::var(IDEMPOTENCY_JOURNAL_PATH_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        Ok(Some(Arc::new(Self::open(path)?)))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn begin(
        self: &Arc<Self>,
        idempotency_key_hex: String,
        request_digest_hex: String,
    ) -> Result<IdempotencyDecision, IdempotencyError> {
        let mut state = self.state.lock().await;

        match state.entries.get(&idempotency_key_hex) {
            Some(IdempotencyEntry::Pending {
                request_digest_hex: existing_digest,
            }) if existing_digest == &request_digest_hex => {
                return Err(IdempotencyError::InProgress);
            }
            Some(IdempotencyEntry::Pending { .. }) => {
                return Err(IdempotencyError::Conflict);
            }
            Some(IdempotencyEntry::Succeeded {
                request_digest_hex: existing_digest,
                response,
            }) if existing_digest == &request_digest_hex => {
                return Ok(IdempotencyDecision::Replay(response.clone()));
            }
            Some(IdempotencyEntry::Succeeded { .. }) => {
                return Err(IdempotencyError::Conflict);
            }
            None => {}
        }

        self.append_event_locked(
            &mut state,
            IdempotencyJournalEvent::Started {
                idempotency_key_hex: idempotency_key_hex.clone(),
                request_digest_hex: request_digest_hex.clone(),
            },
        )
        .await
        .map_err(|err| IdempotencyError::StoreUnavailable(err.to_string()))?;

        state.entries.insert(
            idempotency_key_hex.clone(),
            IdempotencyEntry::Pending {
                request_digest_hex: request_digest_hex.clone(),
            },
        );

        Ok(IdempotencyDecision::Fresh(IdempotencyReservation {
            store: self.clone(),
            idempotency_key_hex,
            request_digest_hex,
        }))
    }

    fn load_records(path: &Path) -> Result<Vec<IdempotencyJournalRecord>> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to read idempotency journal at {}", path.display())
                });
            }
        };

        content
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                serde_json::from_str::<IdempotencyJournalRecord>(line).with_context(|| {
                    format!(
                        "failed to parse idempotency journal line {} at {}",
                        index + 1,
                        path.display()
                    )
                })
            })
            .collect()
    }

    async fn append_event_locked(
        &self,
        state: &mut IdempotencyState,
        event: IdempotencyJournalEvent,
    ) -> Result<()> {
        let recorded_at_unix_ms = unix_ms_now()?;
        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        let record = IdempotencyJournalRecord {
            version: JOURNAL_RECORD_VERSION,
            event_id: format!("{recorded_at_unix_ms}-{sequence}"),
            recorded_at_unix_ms,
            event,
        };
        let line = serde_json::to_string(&record)
            .context("failed to serialize idempotency journal event")?;

        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "failed to create idempotency journal directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .with_context(|| {
                format!(
                    "failed to open idempotency journal for append at {}",
                    self.path.display()
                )
            })?;

        file.write_all(line.as_bytes())
            .await
            .context("failed to append idempotency journal event")?;
        file.write_all(b"\n")
            .await
            .context("failed to terminate idempotency journal event")?;
        file.flush()
            .await
            .context("failed to flush idempotency journal event")?;

        Ok(())
    }
}

impl IdempotencyReservation {
    pub async fn succeed(self, response: StoredIdempotencyResponse) -> Result<()> {
        let mut state = self.store.state.lock().await;
        let idempotency_key_hex = self.idempotency_key_hex;
        let request_digest_hex = self.request_digest_hex;
        self.store
            .append_event_locked(
                &mut state,
                IdempotencyJournalEvent::Succeeded {
                    idempotency_key_hex: idempotency_key_hex.clone(),
                    request_digest_hex: request_digest_hex.clone(),
                    response: response.clone(),
                },
            )
            .await?;

        state.entries.insert(
            idempotency_key_hex,
            IdempotencyEntry::Succeeded {
                request_digest_hex,
                response,
            },
        );

        Ok(())
    }

    pub async fn fail(self, error: impl Into<String>) -> Result<()> {
        let mut state = self.store.state.lock().await;
        let idempotency_key_hex = self.idempotency_key_hex;
        self.store
            .append_event_locked(
                &mut state,
                IdempotencyJournalEvent::Failed {
                    idempotency_key_hex: idempotency_key_hex.clone(),
                    request_digest_hex: self.request_digest_hex,
                    error: error.into(),
                },
            )
            .await?;

        state.entries.remove(&idempotency_key_hex);

        Ok(())
    }
}

pub async fn begin_from_headers(
    store: Option<&Arc<GatewayIdempotencyStore>>,
    headers: &HeaderMap,
    request_digest_hex: String,
) -> Result<Option<IdempotencyDecision>, IdempotencyError> {
    let Some(idempotency_key_hex) = parse_optional_idempotency_key(headers)? else {
        return Ok(None);
    };

    let Some(store) = store else {
        return Err(IdempotencyError::StoreNotConfigured);
    };

    store
        .begin(idempotency_key_hex, request_digest_hex)
        .await
        .map(Some)
}

pub fn parse_optional_idempotency_key(
    headers: &HeaderMap,
) -> Result<Option<String>, IdempotencyError> {
    let Some(value) = headers.get(IDEMPOTENCY_KEY_HEADER) else {
        return Ok(None);
    };

    parse_idempotency_key(value).map(Some)
}

pub fn parse_idempotency_key(value: &HeaderValue) -> Result<String, IdempotencyError> {
    let value = value
        .to_str()
        .map_err(|_| IdempotencyError::InvalidKey)?
        .trim()
        .trim_start_matches("0x");

    if value.is_empty() {
        return Err(IdempotencyError::InvalidKey);
    }

    let bytes = hex::decode(value).map_err(|_| IdempotencyError::InvalidKey)?;
    if bytes.len() != 32 {
        return Err(IdempotencyError::InvalidKey);
    }

    Ok(hex::encode(bytes))
}

pub fn request_digest_hex(domain: &str, parts: &[DigestPart<'_>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());

    for part in parts {
        match part {
            DigestPart::Bytes(bytes) => {
                hasher.update([0]);
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
            DigestPart::String(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
            DigestPart::Bool(value) => {
                hasher.update([2]);
                hasher.update([u8::from(*value)]);
            }
            DigestPart::U32(value) => {
                hasher.update([3]);
                hasher.update(value.to_le_bytes());
            }
            DigestPart::U64(value) => {
                hasher.update([4]);
                hasher.update(value.to_le_bytes());
            }
            DigestPart::OptionalString(value) => {
                hasher.update([5]);
                match value {
                    Some(value) => {
                        hasher.update([1]);
                        hasher.update((value.len() as u64).to_le_bytes());
                        hasher.update(value.as_bytes());
                    }
                    None => hasher.update([0]),
                }
            }
        }
    }

    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, Copy)]
pub enum DigestPart<'a> {
    Bytes(&'a [u8]),
    String(&'a str),
    Bool(bool),
    U32(u32),
    U64(u64),
    OptionalString(Option<&'a str>),
}

pub fn stored_response_from_response(response: &Response) -> StoredIdempotencyResponse {
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| StoredHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect();

    StoredIdempotencyResponse {
        status: response.status().as_u16(),
        headers,
        json_body: None,
    }
}

pub fn stored_json_response<T: Serialize>(
    status: StatusCode,
    response: &T,
) -> Result<StoredIdempotencyResponse> {
    Ok(StoredIdempotencyResponse {
        status: status.as_u16(),
        headers: Vec::new(),
        json_body: Some(serde_json::to_value(response)?),
    })
}

pub async fn persist_http_success(
    reservation: Option<IdempotencyReservation>,
    response: &Response,
) -> Result<()> {
    if let Some(reservation) = reservation {
        reservation
            .succeed(stored_response_from_response(response))
            .await?;
    }

    Ok(())
}

pub async fn persist_stored_success(
    reservation: Option<IdempotencyReservation>,
    response: StoredIdempotencyResponse,
) -> Result<()> {
    if let Some(reservation) = reservation {
        reservation.succeed(response).await?;
    }

    Ok(())
}

pub fn stored_empty_response(status: StatusCode) -> StoredIdempotencyResponse {
    StoredIdempotencyResponse {
        status: status.as_u16(),
        headers: Vec::new(),
        json_body: None,
    }
}

pub fn stored_header_response(
    status: StatusCode,
    headers: Vec<StoredHeader>,
) -> StoredIdempotencyResponse {
    StoredIdempotencyResponse {
        status: status.as_u16(),
        headers,
        json_body: None,
    }
}

pub async fn persist_json_success<T: Serialize>(
    reservation: Option<IdempotencyReservation>,
    status: StatusCode,
    response: &T,
) -> Result<()> {
    if let Some(reservation) = reservation {
        reservation
            .succeed(stored_json_response(status, response)?)
            .await?;
    }

    Ok(())
}

pub async fn persist_failure(
    reservation: Option<IdempotencyReservation>,
    error: impl Into<String>,
) -> Result<()> {
    if let Some(reservation) = reservation {
        reservation.fail(error).await?;
    }

    Ok(())
}

pub fn s3_idempotency_error_response(error: IdempotencyError, resource: String) -> Response {
    let kind = match error {
        IdempotencyError::InvalidKey | IdempotencyError::StoreNotConfigured => {
            S3ErrorKind::InvalidRequest
        }
        IdempotencyError::StoreUnavailable(_) => S3ErrorKind::InternalError,
        IdempotencyError::InProgress | IdempotencyError::Conflict => {
            S3ErrorKind::IdempotencyConflict
        }
    };

    S3ErrorResponse::new(kind)
        .with_message(error.to_string())
        .with_resource(resource)
        .into_response()
}

pub fn s3_idempotency_persist_error_response(
    error: impl std::fmt::Display,
    resource: String,
) -> Response {
    S3ErrorResponse::new(S3ErrorKind::InternalError)
        .with_message(format!(
            "failed to persist idempotency journal result: {error}"
        ))
        .with_resource(resource)
        .into_response()
}

pub async fn s3_complete_http_response(
    reservation: Option<IdempotencyReservation>,
    response: Response,
    resource: String,
) -> Response {
    if let Err(error) = persist_http_success(reservation, &response).await {
        return s3_idempotency_persist_error_response(error, resource);
    }

    response
}

pub async fn s3_record_failure(
    reservation: Option<IdempotencyReservation>,
    error: impl Into<String>,
) {
    if let Err(err) = persist_failure(reservation, error).await {
        warn!("failed to persist idempotency failure: {err}");
    }
}

pub fn replay_http_response(stored: StoredIdempotencyResponse) -> Response {
    let status = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    let mut response = status.into_response();

    for header in stored.headers {
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&header.value) else {
            continue;
        };
        response.headers_mut().insert(name, value);
    }

    response
}

fn replay_records(
    records: Vec<IdempotencyJournalRecord>,
) -> Result<HashMap<String, IdempotencyEntry>> {
    let mut entries = HashMap::new();

    for record in records {
        if record.version != JOURNAL_RECORD_VERSION {
            continue;
        }

        match record.event {
            IdempotencyJournalEvent::Started {
                idempotency_key_hex,
                request_digest_hex,
            } => {
                entries.insert(
                    idempotency_key_hex,
                    IdempotencyEntry::Pending { request_digest_hex },
                );
            }
            IdempotencyJournalEvent::Succeeded {
                idempotency_key_hex,
                request_digest_hex,
                response,
            } => {
                entries.insert(
                    idempotency_key_hex,
                    IdempotencyEntry::Succeeded {
                        request_digest_hex,
                        response,
                    },
                );
            }
            IdempotencyJournalEvent::Failed {
                idempotency_key_hex,
                ..
            } => {
                entries.remove(&idempotency_key_hex);
            }
        }
    }

    Ok(entries)
}

fn unix_ms_now() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(elapsed.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn test_path(name: &str) -> PathBuf {
        let unique = unix_ms_now().unwrap();
        std::env::temp_dir().join(format!(
            "s3gw-idempotency-{name}-{}-{unique}.jsonl",
            std::process::id()
        ))
    }

    fn key(n: u8) -> HeaderValue {
        HeaderValue::from_str(&hex::encode([n; 32])).unwrap()
    }

    #[tokio::test]
    async fn idempotency_store_replays_success_for_same_digest() {
        let store = Arc::new(GatewayIdempotencyStore::open(test_path("replay")).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, key(1));

        let first = begin_from_headers(Some(&store), &headers, "aa".repeat(32))
            .await
            .unwrap()
            .unwrap();

        let IdempotencyDecision::Fresh(reservation) = first else {
            panic!("first request must reserve the idempotency key");
        };

        reservation
            .succeed(StoredIdempotencyResponse {
                status: 200,
                headers: vec![StoredHeader {
                    name: "x-amz-meta-swarm-ref".to_string(),
                    value: "bb".repeat(32),
                }],
                json_body: None,
            })
            .await
            .unwrap();

        let replay = begin_from_headers(Some(&store), &headers, "aa".repeat(32))
            .await
            .unwrap()
            .unwrap();

        let IdempotencyDecision::Replay(response) = replay else {
            panic!("second matching request must replay the stored response");
        };

        assert_eq!(response.status, 200);
        assert_eq!(response.headers[0].value, "bb".repeat(32));
    }

    #[tokio::test]
    async fn idempotency_store_rejects_digest_conflict_and_in_progress_retry() {
        let store = Arc::new(GatewayIdempotencyStore::open(test_path("conflict")).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(IDEMPOTENCY_KEY_HEADER, key(2));

        let first = begin_from_headers(Some(&store), &headers, "aa".repeat(32))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, IdempotencyDecision::Fresh(_)));

        let in_progress = begin_from_headers(Some(&store), &headers, "aa".repeat(32))
            .await
            .unwrap_err();
        assert_eq!(in_progress, IdempotencyError::InProgress);

        let conflict = begin_from_headers(Some(&store), &headers, "bb".repeat(32))
            .await
            .unwrap_err();
        assert_eq!(conflict, IdempotencyError::Conflict);
    }

    #[tokio::test]
    async fn idempotency_store_reloads_success_and_pending_records() {
        let path = test_path("reload");
        let store = Arc::new(GatewayIdempotencyStore::open(&path).unwrap());

        let fresh = store
            .begin(hex::encode([3u8; 32]), "aa".repeat(32))
            .await
            .unwrap();
        let IdempotencyDecision::Fresh(reservation) = fresh else {
            panic!("fresh key should reserve");
        };
        reservation
            .succeed(StoredIdempotencyResponse {
                status: 204,
                headers: Vec::new(),
                json_body: None,
            })
            .await
            .unwrap();

        let pending = store
            .begin(hex::encode([4u8; 32]), "cc".repeat(32))
            .await
            .unwrap();
        assert!(matches!(pending, IdempotencyDecision::Fresh(_)));

        let reloaded = Arc::new(GatewayIdempotencyStore::open(&path).unwrap());

        assert!(matches!(
            reloaded
                .begin(hex::encode([3u8; 32]), "aa".repeat(32))
                .await
                .unwrap(),
            IdempotencyDecision::Replay(_)
        ));
        assert_eq!(
            reloaded
                .begin(hex::encode([4u8; 32]), "cc".repeat(32))
                .await
                .unwrap_err(),
            IdempotencyError::InProgress
        );
    }

    #[test]
    fn idempotency_key_requires_random_sized_hex() {
        assert!(parse_idempotency_key(&key(5)).is_ok());
        assert_eq!(
            parse_idempotency_key(&HeaderValue::from_static("not-hex")).unwrap_err(),
            IdempotencyError::InvalidKey
        );
        assert_eq!(
            parse_idempotency_key(&HeaderValue::from_static("aa")).unwrap_err(),
            IdempotencyError::InvalidKey
        );
    }

    #[test]
    fn request_digest_is_domain_separated_and_type_delimited() {
        let digest = request_digest_hex(
            "s3gw/idempotency/v1/test",
            &[
                DigestPart::String("bucket"),
                DigestPart::Bytes(&[1, 2, 3]),
                DigestPart::OptionalString(None),
            ],
        );
        let changed = request_digest_hex(
            "s3gw/idempotency/v1/test",
            &[
                DigestPart::String("bucket"),
                DigestPart::Bytes(&[1, 2, 3]),
                DigestPart::OptionalString(Some("")),
            ],
        );

        assert_ne!(digest, changed);
        assert_eq!(digest.len(), 64);
    }
}
