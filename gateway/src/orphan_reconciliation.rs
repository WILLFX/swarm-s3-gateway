use crate::bee::client::{BeePutBytesResult, BeeStorage, FeedPointerResult};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    env,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

pub const WRITE_JOURNAL_PATH_ENV: &str = "S3GW_BEE_WRITE_JOURNAL_PATH";
const JOURNAL_RECORD_VERSION: u32 = 1;

#[derive(Debug)]
pub struct GatewayWriteJournal {
    path: PathBuf,
    next_sequence: AtomicU64,
    write_lock: Mutex<()>,
}

impl GatewayWriteJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            next_sequence: AtomicU64::new(1),
            write_lock: Mutex::new(()),
        }
    }

    pub fn from_env() -> Result<Option<Arc<Self>>> {
        let Some(path) = env::var(WRITE_JOURNAL_PATH_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };

        Ok(Some(Arc::new(Self::new(path))))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn append_event(&self, event: GatewayWriteJournalEvent) -> Result<String> {
        let recorded_at_unix_ms = unix_ms_now()?;
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let event_id = format!("{recorded_at_unix_ms}-{sequence}");
        let record = GatewayWriteJournalRecord {
            version: JOURNAL_RECORD_VERSION,
            event_id: event_id.clone(),
            recorded_at_unix_ms,
            event,
        };
        let line = serde_json::to_string(&record)
            .context("failed to serialize Bee write journal event")?;

        let _guard = self.write_lock.lock().await;

        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "failed to create Bee write journal directory {}",
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
                    "failed to open Bee write journal for append at {}",
                    self.path.display()
                )
            })?;

        file.write_all(line.as_bytes())
            .await
            .context("failed to append Bee write journal event")?;
        file.write_all(b"\n")
            .await
            .context("failed to terminate Bee write journal event")?;
        file.flush()
            .await
            .context("failed to flush Bee write journal event")?;

        Ok(event_id)
    }

    pub fn load_records(path: impl AsRef<Path>) -> Result<Vec<GatewayWriteJournalRecord>> {
        let path = path.as_ref();
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to read Bee write journal at {}", path.display())
                });
            }
        };

        content
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                serde_json::from_str::<GatewayWriteJournalRecord>(line).with_context(|| {
                    format!(
                        "failed to parse Bee write journal line {} at {}",
                        index + 1,
                        path.display()
                    )
                })
            })
            .collect()
    }

    pub async fn record_bee_write(&self, event: BeeWriteEvent) -> Result<String> {
        self.append_event(GatewayWriteJournalEvent::BeeWrite(event))
            .await
    }

    pub async fn record_anchor_attempt(&self, event: AnchorAttemptEvent) -> Result<String> {
        self.append_event(GatewayWriteJournalEvent::AnchorAttempt(event))
            .await
    }

    pub async fn record_anchor_result(&self, event: AnchorResultEvent) -> Result<String> {
        self.append_event(GatewayWriteJournalEvent::AnchorResult(event))
            .await
    }
}

fn unix_ms_now() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    Ok(elapsed.as_millis() as u64)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayWriteJournalRecord {
    pub version: u32,
    pub event_id: String,
    pub recorded_at_unix_ms: u64,
    pub event: GatewayWriteJournalEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum GatewayWriteJournalEvent {
    BeeWrite(BeeWriteEvent),
    AnchorAttempt(AnchorAttemptEvent),
    AnchorResult(AnchorResultEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeeWriteEvent {
    pub references: Vec<GatewayBeeReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorAttemptEvent {
    pub action: AnchorJournalAction,
    pub bucket: String,
    pub owner_hex: String,
    pub bucket_id_hex: String,
    pub bucket_type: JournalBucketType,
    pub expected_bucket_manifest_root_hex: String,
    pub new_bucket_manifest_root_hex: String,
    pub references: Vec<GatewayBeeReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorResultEvent {
    pub attempt_event_id: String,
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnchorJournalAction {
    PublicPut,
    TrustedPrivatePut,
    PublicDelete,
    TrustedPrivateDelete,
    TrustlessPutEncryptedManifest,
    TrustlessDeleteEncryptedManifest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum JournalBucketType {
    Public,
    TrustedGatewayPrivate,
    TrustlessPrivate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GatewayBeeReference {
    pub reference_hex: String,
    pub kind: GatewayBeeReferenceKind,
}

impl GatewayBeeReference {
    pub fn new(reference_hex: impl Into<String>, kind: GatewayBeeReferenceKind) -> Self {
        Self {
            reference_hex: reference_hex.into(),
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GatewayBeeReferenceKind {
    UnknownBytes,
    PointerPayload,
    FeedManifest,
    SocPointer,
    PublicObjectPayload,
    PublicObjectManifest,
    PublicBucketManifest,
    PrivateObjectPayload,
    PrivateObjectManifest,
    PrivateBucketManifest,
    TrustlessEncryptedManifest,
    TrustlessCiphertextPayload,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationReportStatus {
    AutoUnpinCandidate,
    ReportOnly,
    NotProvenUnreachable,
    ManifestHolderProofRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationProofRequirement {
    ChainReachabilityCheck,
    ManifestHolderReachabilityProof,
}

pub async fn record_anchor_attempt(
    journal: Option<&Arc<GatewayWriteJournal>>,
    event: AnchorAttemptEvent,
) -> Result<Option<String>> {
    match journal {
        Some(journal) => journal.record_anchor_attempt(event).await.map(Some),
        None => Ok(None),
    }
}

pub async fn record_anchor_success(
    journal: Option<&Arc<GatewayWriteJournal>>,
    attempt_event_id: Option<String>,
    tx_hash: String,
) -> Result<()> {
    let (Some(journal), Some(attempt_event_id)) = (journal, attempt_event_id) else {
        return Ok(());
    };

    journal
        .record_anchor_result(AnchorResultEvent {
            attempt_event_id,
            succeeded: true,
            tx_hash: Some(tx_hash),
            error: None,
        })
        .await?;
    Ok(())
}

pub async fn record_anchor_failure(
    journal: Option<&Arc<GatewayWriteJournal>>,
    attempt_event_id: Option<String>,
    error: &anyhow::Error,
) -> Result<()> {
    let (Some(journal), Some(attempt_event_id)) = (journal, attempt_event_id) else {
        return Ok(());
    };

    journal
        .record_anchor_result(AnchorResultEvent {
            attempt_event_id,
            succeeded: false,
            tx_hash: None,
            error: Some(error.to_string()),
        })
        .await?;
    Ok(())
}

pub struct JournaledBeeStorage {
    inner: Arc<dyn BeeStorage>,
    journal: Arc<GatewayWriteJournal>,
}

impl JournaledBeeStorage {
    pub fn new(inner: Arc<dyn BeeStorage>, journal: Arc<GatewayWriteJournal>) -> Self {
        Self { inner, journal }
    }
}

#[async_trait]
impl BeeStorage for JournaledBeeStorage {
    async fn get_bytes(&self, reference: &str) -> Result<Option<Bytes>> {
        self.inner.get_bytes(reference).await
    }

    async fn put_bytes(&self, data: Bytes) -> Result<BeePutBytesResult> {
        let result = self.inner.put_bytes(data).await?;
        self.journal
            .record_bee_write(BeeWriteEvent {
                references: vec![GatewayBeeReference::new(
                    result.reference.clone(),
                    GatewayBeeReferenceKind::UnknownBytes,
                )],
                bucket: None,
                key: None,
                topic_hex: None,
            })
            .await?;
        Ok(result)
    }

    async fn get_pointer_bytes(&self, topic: [u8; 32]) -> Result<Option<Vec<u8>>> {
        self.inner.get_pointer_bytes(topic).await
    }

    async fn put_object_and_update_pointer(
        &self,
        bucket: &str,
        key: &str,
        data: Bytes,
    ) -> Result<FeedPointerResult> {
        let result = self
            .inner
            .put_object_and_update_pointer(bucket, key, data)
            .await?;
        self.journal
            .record_bee_write(BeeWriteEvent {
                references: vec![
                    GatewayBeeReference::new(
                        result.swarm_reference.clone(),
                        GatewayBeeReferenceKind::PointerPayload,
                    ),
                    GatewayBeeReference::new(
                        result.manifest_reference.clone(),
                        GatewayBeeReferenceKind::FeedManifest,
                    ),
                    GatewayBeeReference::new(
                        result.soc_reference.clone(),
                        GatewayBeeReferenceKind::SocPointer,
                    ),
                ],
                bucket: Some(bucket.to_string()),
                key: Some(key.to_string()),
                topic_hex: Some(result.topic_hex.clone()),
            })
            .await?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationCandidateSeed {
    pub attempt_event_id: String,
    pub action: AnchorJournalAction,
    pub bucket: String,
    pub owner_hex: String,
    pub bucket_id_hex: String,
    pub bucket_type: JournalBucketType,
    pub reference: GatewayBeeReference,
    pub auto_unpin_allowed: bool,
    pub report_status: ReconciliationReportStatus,
    pub proof_required: Option<ReconciliationProofRequirement>,
    pub policy_reason: String,
}

pub fn collect_anchor_attempt_candidates(
    records: &[GatewayWriteJournalRecord],
) -> Vec<ReconciliationCandidateSeed> {
    let mut attempts = Vec::new();
    let mut successful_attempt_ids = HashSet::new();
    let mut successful_references = HashSet::new();
    let mut failed_attempt_ids = HashSet::new();

    for record in records {
        match &record.event {
            GatewayWriteJournalEvent::AnchorAttempt(event) => {
                attempts.push((record.event_id.clone(), event.clone()));
            }
            GatewayWriteJournalEvent::AnchorResult(event) if event.succeeded => {
                successful_attempt_ids.insert(event.attempt_event_id.clone());
            }
            GatewayWriteJournalEvent::AnchorResult(event) => {
                failed_attempt_ids.insert(event.attempt_event_id.clone());
            }
            GatewayWriteJournalEvent::BeeWrite(_) => {}
        }
    }

    for (attempt_id, attempt) in &attempts {
        if successful_attempt_ids.contains(attempt_id) {
            for reference in &attempt.references {
                successful_references.insert(reference.reference_hex.clone());
            }
        }
    }

    attempts
        .into_iter()
        .filter(|(attempt_id, _)| {
            failed_attempt_ids.contains(attempt_id) || !successful_attempt_ids.contains(attempt_id)
        })
        .flat_map(|(attempt_event_id, attempt)| {
            let failed = failed_attempt_ids.contains(&attempt_event_id);
            attempt
                .references
                .into_iter()
                .map({
                    let attempt_event_id = attempt_event_id.clone();
                    let successful_references = successful_references.clone();
                    move |reference| {
                        let policy = reference_policy(
                            reference.kind,
                            &reference.reference_hex,
                            failed,
                            &successful_references,
                        );
                        ReconciliationCandidateSeed {
                            attempt_event_id: attempt_event_id.clone(),
                            action: attempt.action,
                            bucket: attempt.bucket.clone(),
                            owner_hex: attempt.owner_hex.clone(),
                            bucket_id_hex: attempt.bucket_id_hex.clone(),
                            bucket_type: attempt.bucket_type,
                            reference,
                            auto_unpin_allowed: policy.auto_unpin_allowed,
                            report_status: policy.report_status,
                            proof_required: policy.proof_required,
                            policy_reason: policy.reason,
                        }
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

pub fn collect_reference_usage(
    records: &[GatewayWriteJournalRecord],
) -> HashMap<String, HashSet<String>> {
    let mut usage: HashMap<String, HashSet<String>> = HashMap::new();

    for record in records {
        let references = match &record.event {
            GatewayWriteJournalEvent::BeeWrite(event) => &event.references,
            GatewayWriteJournalEvent::AnchorAttempt(event) => &event.references,
            GatewayWriteJournalEvent::AnchorResult(_) => continue,
        };

        for reference in references {
            usage
                .entry(reference.reference_hex.clone())
                .or_default()
                .insert(record.event_id.clone());
        }
    }

    usage
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferencePolicy {
    auto_unpin_allowed: bool,
    report_status: ReconciliationReportStatus,
    proof_required: Option<ReconciliationProofRequirement>,
    reason: String,
}

fn reference_policy(
    kind: GatewayBeeReferenceKind,
    reference_hex: &str,
    failed: bool,
    successful_references: &HashSet<String>,
) -> ReferencePolicy {
    if !failed {
        return ReferencePolicy {
            auto_unpin_allowed: false,
            report_status: ReconciliationReportStatus::ReportOnly,
            proof_required: None,
            reason: "anchor result is pending; automatic unpin is unsafe while a request may still be in flight"
                .to_string(),
        };
    }

    if successful_references.contains(reference_hex) {
        return ReferencePolicy {
            auto_unpin_allowed: false,
            report_status: ReconciliationReportStatus::NotProvenUnreachable,
            proof_required: None,
            reason: "reference also appears in a successful anchor attempt".to_string(),
        };
    }

    match kind {
        GatewayBeeReferenceKind::TrustlessCiphertextPayload => ReferencePolicy {
            auto_unpin_allowed: false,
            report_status: ReconciliationReportStatus::ManifestHolderProofRequired,
            proof_required: Some(ReconciliationProofRequirement::ManifestHolderReachabilityProof),
            reason: "trustless ciphertext payload is report_only: gateway cannot decrypt trustless manifests to prove reachability; manifest-holder proof is required before deletion"
                .to_string(),
        },
        GatewayBeeReferenceKind::FeedManifest
        | GatewayBeeReferenceKind::SocPointer
        | GatewayBeeReferenceKind::UnknownBytes
        | GatewayBeeReferenceKind::PointerPayload => ReferencePolicy {
            auto_unpin_allowed: false,
            report_status: ReconciliationReportStatus::ReportOnly,
            proof_required: None,
            reason: "reference is not tied to a typed failed chain anchor attempt".to_string(),
        },
        _ => ReferencePolicy {
            auto_unpin_allowed: true,
            report_status: ReconciliationReportStatus::AutoUnpinCandidate,
            proof_required: Some(ReconciliationProofRequirement::ChainReachabilityCheck),
            reason: "reference belongs to a failed typed chain anchor attempt and still requires per-bucket chain reachability verification before unpin".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(event_id: &str, event: GatewayWriteJournalEvent) -> GatewayWriteJournalRecord {
        GatewayWriteJournalRecord {
            version: JOURNAL_RECORD_VERSION,
            event_id: event_id.to_string(),
            recorded_at_unix_ms: 1,
            event,
        }
    }

    fn attempt(reference: &str, kind: GatewayBeeReferenceKind) -> AnchorAttemptEvent {
        AnchorAttemptEvent {
            action: AnchorJournalAction::PublicPut,
            bucket: "bucket".to_string(),
            owner_hex: "11".repeat(32),
            bucket_id_hex: "22".repeat(32),
            bucket_type: JournalBucketType::Public,
            expected_bucket_manifest_root_hex: String::new(),
            new_bucket_manifest_root_hex: reference.to_string(),
            references: vec![GatewayBeeReference::new(reference, kind)],
        }
    }

    #[test]
    fn failed_anchor_attempt_becomes_candidate() {
        let records = vec![
            record(
                "attempt-1",
                GatewayWriteJournalEvent::AnchorAttempt(attempt(
                    &"aa".repeat(32),
                    GatewayBeeReferenceKind::PublicBucketManifest,
                )),
            ),
            record(
                "result-1",
                GatewayWriteJournalEvent::AnchorResult(AnchorResultEvent {
                    attempt_event_id: "attempt-1".to_string(),
                    succeeded: false,
                    tx_hash: None,
                    error: Some("stale root".to_string()),
                }),
            ),
        ];

        let candidates = collect_anchor_attempt_candidates(&records);

        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].auto_unpin_allowed);
        assert_eq!(
            candidates[0].report_status,
            ReconciliationReportStatus::AutoUnpinCandidate
        );
        assert_eq!(
            candidates[0].proof_required,
            Some(ReconciliationProofRequirement::ChainReachabilityCheck)
        );
    }

    #[test]
    fn successful_anchor_attempt_is_not_candidate() {
        let records = vec![
            record(
                "attempt-1",
                GatewayWriteJournalEvent::AnchorAttempt(attempt(
                    &"aa".repeat(32),
                    GatewayBeeReferenceKind::PublicBucketManifest,
                )),
            ),
            record(
                "result-1",
                GatewayWriteJournalEvent::AnchorResult(AnchorResultEvent {
                    attempt_event_id: "attempt-1".to_string(),
                    succeeded: true,
                    tx_hash: Some("tx".to_string()),
                    error: None,
                }),
            ),
        ];

        assert!(collect_anchor_attempt_candidates(&records).is_empty());
    }

    #[test]
    fn trustless_ciphertext_payload_is_report_only() {
        let records = vec![record(
            "attempt-1",
            GatewayWriteJournalEvent::AnchorAttempt(attempt(
                &"aa".repeat(32),
                GatewayBeeReferenceKind::TrustlessCiphertextPayload,
            )),
        )];

        let candidates = collect_anchor_attempt_candidates(&records);

        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].auto_unpin_allowed);
        assert_eq!(
            candidates[0].report_status,
            ReconciliationReportStatus::ReportOnly
        );
        assert!(candidates[0].policy_reason.contains("pending"));
    }

    #[test]
    fn pending_anchor_attempt_is_report_only() {
        let records = vec![record(
            "attempt-1",
            GatewayWriteJournalEvent::AnchorAttempt(attempt(
                &"aa".repeat(32),
                GatewayBeeReferenceKind::PublicBucketManifest,
            )),
        )];

        let candidates = collect_anchor_attempt_candidates(&records);

        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].auto_unpin_allowed);
        assert_eq!(
            candidates[0].report_status,
            ReconciliationReportStatus::ReportOnly
        );
        assert!(candidates[0].policy_reason.contains("pending"));
    }

    #[test]
    fn failed_trustless_ciphertext_payload_is_report_only() {
        let records = vec![
            record(
                "attempt-1",
                GatewayWriteJournalEvent::AnchorAttempt(attempt(
                    &"aa".repeat(32),
                    GatewayBeeReferenceKind::TrustlessCiphertextPayload,
                )),
            ),
            record(
                "result-1",
                GatewayWriteJournalEvent::AnchorResult(AnchorResultEvent {
                    attempt_event_id: "attempt-1".to_string(),
                    succeeded: false,
                    tx_hash: None,
                    error: Some("stale root".to_string()),
                }),
            ),
        ];

        let candidates = collect_anchor_attempt_candidates(&records);

        assert_eq!(candidates.len(), 1);
        assert!(!candidates[0].auto_unpin_allowed);
        assert_eq!(
            candidates[0].report_status,
            ReconciliationReportStatus::ManifestHolderProofRequired
        );
        assert_eq!(
            candidates[0].proof_required,
            Some(ReconciliationProofRequirement::ManifestHolderReachabilityProof)
        );
        assert!(candidates[0].policy_reason.contains("cannot decrypt"));
        assert!(candidates[0]
            .policy_reason
            .contains("manifest-holder proof"));
    }
}
