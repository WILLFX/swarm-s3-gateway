use std::{env, fmt, time::Duration};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
use crate::planner::RemoteGatewayAction;
use crate::remote_gateway::{RemoteGatewayClientError, TrustlessRemoteGatewayClient};

const CIPHERTEXT_GATEWAY_PATH: &str = "/trustless/v1/ciphertext-gateway";
const WIRE_VERSION: u32 = 1;

const REMOTE_GATEWAY_ACCESS_KEY_ID_ENV: &str = "TRUSTLESS_PROXY_REMOTE_GATEWAY_ACCESS_KEY_ID";
const REMOTE_GATEWAY_SECRET_ACCESS_KEY_ENV: &str =
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_SECRET_ACCESS_KEY";
const REMOTE_GATEWAY_REGION_ENV: &str = "TRUSTLESS_PROXY_REMOTE_GATEWAY_REGION";
const REMOTE_GATEWAY_SERVICE_ENV: &str = "TRUSTLESS_PROXY_REMOTE_GATEWAY_SERVICE";
const REMOTE_GATEWAY_HTTP_TIMEOUT_SECS_ENV: &str =
    "TRUSTLESS_PROXY_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS";

const DEFAULT_SIGV4_REGION: &str = "us-east-1";
const DEFAULT_SIGV4_SERVICE: &str = "s3";
const DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS: u64 = 30;
const SIGV4_SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGatewayHttpClientConfig {
    pub base_url: String,
    pub sigv4_auth: Option<RemoteGatewaySigV4AuthConfig>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RemoteGatewaySigV4AuthConfig {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
    pub service: String,
}

impl fmt::Debug for RemoteGatewaySigV4AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteGatewaySigV4AuthConfig")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .field("service", &self.service)
            .finish()
    }
}

impl RemoteGatewaySigV4AuthConfig {
    pub fn from_parts(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        region: impl Into<String>,
        service: impl Into<String>,
    ) -> Result<Self, RemoteGatewayHttpClientError> {
        let access_key_id = access_key_id.into().trim().to_owned();
        let secret_access_key = secret_access_key.into().trim().to_owned();
        let region = region.into().trim().to_owned();
        let service = service.into().trim().to_owned();

        if access_key_id.is_empty() {
            return Err(RemoteGatewayHttpClientError::MissingRemoteGatewayAccessKeyId);
        }

        if secret_access_key.is_empty() {
            return Err(RemoteGatewayHttpClientError::MissingRemoteGatewaySecretAccessKey);
        }

        if region.is_empty() || service.is_empty() {
            return Err(RemoteGatewayHttpClientError::InvalidSigV4Scope);
        }

        Ok(Self {
            access_key_id,
            secret_access_key,
            region,
            service,
        })
    }

    pub fn from_env() -> Result<Option<Self>, RemoteGatewayHttpClientError> {
        let access_key_id = optional_env(REMOTE_GATEWAY_ACCESS_KEY_ID_ENV);
        let secret_access_key = optional_env(REMOTE_GATEWAY_SECRET_ACCESS_KEY_ENV);

        match (access_key_id, secret_access_key) {
            (None, None) => Ok(None),
            (Some(_), None) => {
                Err(RemoteGatewayHttpClientError::MissingRemoteGatewaySecretAccessKey)
            }
            (None, Some(_)) => Err(RemoteGatewayHttpClientError::MissingRemoteGatewayAccessKeyId),
            (Some(access_key_id), Some(secret_access_key)) => {
                let region = optional_env(REMOTE_GATEWAY_REGION_ENV)
                    .unwrap_or_else(|| DEFAULT_SIGV4_REGION.to_owned());
                let service = optional_env(REMOTE_GATEWAY_SERVICE_ENV)
                    .unwrap_or_else(|| DEFAULT_SIGV4_SERVICE.to_owned());

                Self::from_parts(access_key_id, secret_access_key, region, service).map(Some)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteGatewayHttpRequestEnvelope {
    version: u32,
    action: String,
    bucket_id_hex: String,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    ciphertext_reference_hex: Option<String>,
    expected_manifest_reference_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteGatewayHttpResponseEnvelope {
    version: u32,
    action: String,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    ciphertext_reference_hex: Option<String>,
    encrypted_manifest_reference_hex: Option<String>,
    metadata_only: bool,
    gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteGatewayHttpClientError {
    #[error("remote gateway base URL is required")]
    MissingBaseUrl,

    #[error("remote gateway base URL must be an absolute http:// or https:// URL")]
    InvalidBaseUrl,

    #[error("remote gateway HTTP is only allowed for localhost or loopback development URLs")]
    InsecureRemoteGatewayUrl,

    #[error("plaintext payload must never be sent to the remote gateway")]
    PlaintextPayloadRejected,

    #[error("bucket id is required")]
    MissingBucketId,

    #[error("bucket id must be a 32-byte hex value")]
    InvalidBucketId,

    #[error("ciphertext payload is required for PUT ciphertext object")]
    MissingCiphertextPayload,

    #[error("encrypted manifest payload is required for encrypted manifest write")]
    MissingEncryptedManifestPayload,

    #[error("ciphertext reference is required for object read gateway action")]
    MissingCiphertextReference,

    #[error("expected manifest reference is required for DELETE ciphertext object")]
    MissingExpectedManifestReference,

    #[error("request action does not allow ciphertext payload: {0:?}")]
    UnexpectedCiphertextPayload(RemoteGatewayAction),

    #[error("request action does not allow encrypted manifest payload: {0:?}")]
    UnexpectedEncryptedManifestPayload(RemoteGatewayAction),

    #[error("request action does not allow ciphertext reference: {0:?}")]
    UnexpectedCiphertextReference(RemoteGatewayAction),

    #[error("request action does not allow expected manifest reference: {0:?}")]
    UnexpectedExpectedManifestReference(RemoteGatewayAction),

    #[error("unknown remote gateway HTTP action: {0}")]
    UnknownAction(String),

    #[error("remote gateway SigV4 access key id is required when gateway auth is configured")]
    MissingRemoteGatewayAccessKeyId,

    #[error("remote gateway SigV4 secret access key is required when gateway auth is configured")]
    MissingRemoteGatewaySecretAccessKey,

    #[error("remote gateway SigV4 region and service are required")]
    InvalidSigV4Scope,

    #[error("remote gateway HTTP response claimed plaintext access")]
    GatewayPlaintextAccessRejected,

    #[error("remote gateway HTTP decode failed: {0}")]
    Decode(String),

    #[error("remote gateway HTTP transport failed: {0}")]
    Transport(String),
}

impl From<RemoteGatewayHttpClientError> for RemoteGatewayClientError {
    fn from(error: RemoteGatewayHttpClientError) -> Self {
        match error {
            RemoteGatewayHttpClientError::MissingBucketId => {
                RemoteGatewayClientError::MissingBucketId
            }
            RemoteGatewayHttpClientError::InvalidBucketId => {
                RemoteGatewayClientError::InvalidBucketId
            }
            RemoteGatewayHttpClientError::PlaintextPayloadRejected => {
                RemoteGatewayClientError::PlaintextPayloadRejected
            }
            RemoteGatewayHttpClientError::MissingCiphertextPayload => {
                RemoteGatewayClientError::MissingPutCiphertextPayload
            }
            RemoteGatewayHttpClientError::MissingEncryptedManifestPayload => {
                RemoteGatewayClientError::MissingDeleteEncryptedManifestPayload
            }
            RemoteGatewayHttpClientError::MissingCiphertextReference => {
                RemoteGatewayClientError::MissingCiphertextReference
            }
            RemoteGatewayHttpClientError::MissingExpectedManifestReference => {
                RemoteGatewayClientError::MissingExpectedManifestReference
            }
            RemoteGatewayHttpClientError::UnexpectedCiphertextPayload(action) => {
                RemoteGatewayClientError::UnexpectedCiphertextPayload(action)
            }
            RemoteGatewayHttpClientError::UnexpectedEncryptedManifestPayload(action) => {
                RemoteGatewayClientError::UnexpectedEncryptedManifestPayload(action)
            }
            RemoteGatewayHttpClientError::UnexpectedCiphertextReference(action) => {
                RemoteGatewayClientError::UnexpectedCiphertextReference(action)
            }
            RemoteGatewayHttpClientError::UnexpectedExpectedManifestReference(action) => {
                RemoteGatewayClientError::UnexpectedExpectedManifestReference(action)
            }
            RemoteGatewayHttpClientError::GatewayPlaintextAccessRejected => {
                RemoteGatewayClientError::GatewayPlaintextAccessRejected
            }
            other => RemoteGatewayClientError::Http(other.to_string()),
        }
    }
}

pub trait RemoteGatewayHttpTransport {
    fn post_json(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<Vec<u8>, RemoteGatewayHttpClientError>;
}

#[derive(Debug, Clone)]
pub struct ReqwestRemoteGatewayHttpTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestRemoteGatewayHttpTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(remote_gateway_http_timeout_from_env())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client builder accepts configured timeout"),
        }
    }
}

impl Default for ReqwestRemoteGatewayHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteGatewayHttpTransport for ReqwestRemoteGatewayHttpTransport {
    fn post_json(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> Result<Vec<u8>, RemoteGatewayHttpClientError> {
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json");

        for (name, value) in headers {
            request = request.header(name.as_str(), value);
        }

        let response = request
            .body(body)
            .send()
            .map_err(|error| RemoteGatewayHttpClientError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| RemoteGatewayHttpClientError::Transport(error.to_string()))?;

        let bytes = response
            .bytes()
            .map_err(|error| RemoteGatewayHttpClientError::Transport(error.to_string()))?;

        Ok(bytes.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct RemoteGatewayHttpClient<T = ReqwestRemoteGatewayHttpTransport> {
    config: RemoteGatewayHttpClientConfig,
    transport: T,
}

impl RemoteGatewayHttpClient<ReqwestRemoteGatewayHttpTransport> {
    pub fn new(base_url: impl Into<String>) -> Result<Self, RemoteGatewayHttpClientError> {
        Self::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: base_url.into(),
                sigv4_auth: None,
            },
            ReqwestRemoteGatewayHttpTransport::new(),
        )
    }

    pub fn from_env(base_url: impl Into<String>) -> Result<Self, RemoteGatewayHttpClientError> {
        Self::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: base_url.into(),
                sigv4_auth: RemoteGatewaySigV4AuthConfig::from_env()?,
            },
            ReqwestRemoteGatewayHttpTransport::new(),
        )
    }
}

impl<T> RemoteGatewayHttpClient<T>
where
    T: RemoteGatewayHttpTransport,
{
    pub fn with_transport(
        config: RemoteGatewayHttpClientConfig,
        transport: T,
    ) -> Result<Self, RemoteGatewayHttpClientError> {
        validate_base_url(&config.base_url)?;
        if let Some(auth) = &config.sigv4_auth {
            validate_sigv4_auth(auth)?;
        }

        Ok(Self { config, transport })
    }

    pub fn endpoint_url(&self) -> String {
        format!(
            "{}{}",
            self.config.base_url.trim_end_matches('/'),
            CIPHERTEXT_GATEWAY_PATH
        )
    }

    pub fn config(&self) -> &RemoteGatewayHttpClientConfig {
        &self.config
    }
}

impl<T> TrustlessRemoteGatewayClient for RemoteGatewayHttpClient<T>
where
    T: RemoteGatewayHttpTransport,
{
    fn execute_ciphertext_request(
        &self,
        request: CiphertextGatewayRequest,
    ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
        let envelope = request_to_http_envelope(request).map_err(RemoteGatewayClientError::from)?;
        let body = serde_json::to_vec(&envelope)
            .map_err(|error| RemoteGatewayClientError::Http(error.to_string()))?;

        let endpoint_url = self.endpoint_url();
        let headers = build_auth_headers(&self.config, &endpoint_url, &body)
            .map_err(RemoteGatewayClientError::from)?;

        let response_body = self
            .transport
            .post_json(&endpoint_url, body, headers)
            .map_err(RemoteGatewayClientError::from)?;

        let response_envelope: RemoteGatewayHttpResponseEnvelope =
            serde_json::from_slice(&response_body)
                .map_err(|error| RemoteGatewayClientError::Http(error.to_string()))?;

        http_envelope_to_response(response_envelope).map_err(RemoteGatewayClientError::from)
    }
}

fn build_auth_headers(
    config: &RemoteGatewayHttpClientConfig,
    url: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>, RemoteGatewayHttpClientError> {
    let Some(auth) = &config.sigv4_auth else {
        return Ok(Vec::new());
    };

    let amz_date = current_amz_date();
    build_sigv4_headers(auth, url, body, &amz_date)
}

fn build_sigv4_headers(
    auth: &RemoteGatewaySigV4AuthConfig,
    url: &str,
    body: &[u8],
    amz_date: &str,
) -> Result<Vec<(String, String)>, RemoteGatewayHttpClientError> {
    validate_sigv4_auth(auth)?;

    let parsed_url =
        reqwest::Url::parse(url).map_err(|_| RemoteGatewayHttpClientError::InvalidBaseUrl)?;
    let host = host_header(&parsed_url)?;
    let canonical_uri = if parsed_url.path().is_empty() {
        "/"
    } else {
        parsed_url.path()
    };
    let date_scope = amz_date
        .get(..8)
        .ok_or(RemoteGatewayHttpClientError::InvalidSigV4Scope)?;

    let payload_hash = sha256_hex(body);
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");

    let canonical_request = format!(
        "POST\n{canonical_uri}\n\n{canonical_headers}\n{SIGV4_SIGNED_HEADERS}\n{payload_hash}"
    );

    let credential_scope = format!("{date_scope}/{}/{}/aws4_request", auth.region, auth.service);

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let signing_key = sigv4_signing_key(
        &auth.secret_access_key,
        date_scope,
        &auth.region,
        &auth.service,
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={SIGV4_SIGNED_HEADERS}, Signature={signature}",
        auth.access_key_id
    );

    Ok(vec![
        ("host".to_owned(), host),
        ("x-amz-date".to_owned(), amz_date.to_owned()),
        ("x-amz-content-sha256".to_owned(), payload_hash),
        ("authorization".to_owned(), authorization),
    ])
}

fn host_header(url: &reqwest::Url) -> Result<String, RemoteGatewayHttpClientError> {
    let Some(host) = url.host_str() else {
        return Err(RemoteGatewayHttpClientError::InvalidBaseUrl);
    };

    let include_port = match (url.scheme(), url.port()) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => false,
        (_, Some(_)) => true,
    };

    if include_port {
        Ok(format!("{}:{}", host, url.port().unwrap()))
    } else {
        Ok(host.to_owned())
    }
}

fn current_amz_date() -> String {
    let now = OffsetDateTime::now_utc();

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sigv4_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn validate_sigv4_auth(
    auth: &RemoteGatewaySigV4AuthConfig,
) -> Result<(), RemoteGatewayHttpClientError> {
    if auth.access_key_id.trim().is_empty() {
        return Err(RemoteGatewayHttpClientError::MissingRemoteGatewayAccessKeyId);
    }

    if auth.secret_access_key.trim().is_empty() {
        return Err(RemoteGatewayHttpClientError::MissingRemoteGatewaySecretAccessKey);
    }

    if auth.region.trim().is_empty() || auth.service.trim().is_empty() {
        return Err(RemoteGatewayHttpClientError::InvalidSigV4Scope);
    }

    Ok(())
}

fn optional_env(name: &'static str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn remote_gateway_http_timeout_from_env() -> Duration {
    parse_remote_gateway_http_timeout_secs(
        env::var(REMOTE_GATEWAY_HTTP_TIMEOUT_SECS_ENV)
            .ok()
            .as_deref(),
    )
}

fn parse_remote_gateway_http_timeout_secs(raw: Option<&str>) -> Duration {
    let Some(raw) = raw else {
        return Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS);
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS);
    }

    match trimmed.parse::<u64>() {
        Ok(seconds) if seconds > 0 => Duration::from_secs(seconds),
        _ => Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS),
    }
}

fn request_to_http_envelope(
    request: CiphertextGatewayRequest,
) -> Result<RemoteGatewayHttpRequestEnvelope, RemoteGatewayHttpClientError> {
    let bucket_id_hex = validate_bucket_id_hex(&request.bucket_id_hex)?;

    if request.plaintext_payload_present {
        return Err(RemoteGatewayHttpClientError::PlaintextPayloadRejected);
    }

    match request.action {
        RemoteGatewayAction::PutCiphertextObject => {
            let Some(ciphertext) = &request.ciphertext_payload else {
                return Err(RemoteGatewayHttpClientError::MissingCiphertextPayload);
            };

            if ciphertext.is_empty() {
                return Err(RemoteGatewayHttpClientError::MissingCiphertextPayload);
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedEncryptedManifestPayload(
                        request.action,
                    ),
                );
            }

            if request.ciphertext_reference_hex.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextReference(
                    request.action,
                ));
            }

            if request.expected_manifest_reference_hex.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedExpectedManifestReference(
                        request.action,
                    ),
                );
            }
        }
        RemoteGatewayAction::PutEncryptedManifest | RemoteGatewayAction::DeleteCiphertextObject => {
            let Some(encrypted_manifest) = &request.encrypted_manifest_payload else {
                return Err(RemoteGatewayHttpClientError::MissingEncryptedManifestPayload);
            };

            if encrypted_manifest.is_empty() {
                return Err(RemoteGatewayHttpClientError::MissingEncryptedManifestPayload);
            }

            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }

            if request.ciphertext_reference_hex.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextReference(
                    request.action,
                ));
            }

            if matches!(request.action, RemoteGatewayAction::DeleteCiphertextObject) {
                match request.expected_manifest_reference_hex.as_deref() {
                    Some(reference) if !reference.trim().is_empty() => {}
                    _ => {
                        return Err(RemoteGatewayHttpClientError::MissingExpectedManifestReference);
                    }
                }
            }
        }
        RemoteGatewayAction::GetCiphertextObject | RemoteGatewayAction::HeadCiphertextObject => {
            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedEncryptedManifestPayload(
                        request.action,
                    ),
                );
            }

            if request.expected_manifest_reference_hex.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedExpectedManifestReference(
                        request.action,
                    ),
                );
            }

            match request.ciphertext_reference_hex.as_deref() {
                Some(reference) if !reference.trim().is_empty() => {}
                _ => return Err(RemoteGatewayHttpClientError::MissingCiphertextReference),
            }
        }
        RemoteGatewayAction::ListCiphertextManifest
        | RemoteGatewayAction::CreateTrustlessBucket => {
            if request.ciphertext_payload.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextPayload(
                    request.action,
                ));
            }

            if request.encrypted_manifest_payload.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedEncryptedManifestPayload(
                        request.action,
                    ),
                );
            }

            if request.ciphertext_reference_hex.is_some() {
                return Err(RemoteGatewayHttpClientError::UnexpectedCiphertextReference(
                    request.action,
                ));
            }

            if request.expected_manifest_reference_hex.is_some() {
                return Err(
                    RemoteGatewayHttpClientError::UnexpectedExpectedManifestReference(
                        request.action,
                    ),
                );
            }
        }
    }

    Ok(RemoteGatewayHttpRequestEnvelope {
        version: WIRE_VERSION,
        action: action_to_wire(request.action).to_owned(),
        bucket_id_hex,
        ciphertext_hex: request.ciphertext_payload.map(hex::encode),
        encrypted_manifest_hex: request.encrypted_manifest_payload.map(hex::encode),
        ciphertext_reference_hex: request.ciphertext_reference_hex,
        expected_manifest_reference_hex: request.expected_manifest_reference_hex,
    })
}

fn validate_bucket_id_hex(bucket_id_hex: &str) -> Result<String, RemoteGatewayHttpClientError> {
    let bucket_id_hex = bucket_id_hex.trim().trim_start_matches("0x").to_owned();
    if bucket_id_hex.is_empty() {
        return Err(RemoteGatewayHttpClientError::MissingBucketId);
    }

    let bytes =
        hex::decode(&bucket_id_hex).map_err(|_| RemoteGatewayHttpClientError::InvalidBucketId)?;
    if bytes.len() != 32 {
        return Err(RemoteGatewayHttpClientError::InvalidBucketId);
    }

    Ok(bucket_id_hex)
}

fn http_envelope_to_response(
    envelope: RemoteGatewayHttpResponseEnvelope,
) -> Result<CiphertextGatewayResponse, RemoteGatewayHttpClientError> {
    if envelope.gateway_plaintext_access {
        return Err(RemoteGatewayHttpClientError::GatewayPlaintextAccessRejected);
    }

    if envelope.version != WIRE_VERSION {
        return Err(RemoteGatewayHttpClientError::Decode(format!(
            "unsupported wire version {}",
            envelope.version
        )));
    }

    Ok(CiphertextGatewayResponse {
        action: wire_to_action(&envelope.action)?,
        ciphertext_payload: decode_optional_hex(envelope.ciphertext_hex)?,
        encrypted_manifest_payload: decode_optional_hex(envelope.encrypted_manifest_hex)?,
        ciphertext_reference_hex: envelope.ciphertext_reference_hex,
        encrypted_manifest_reference_hex: envelope.encrypted_manifest_reference_hex,
        metadata_only: envelope.metadata_only,
        gateway_plaintext_access: false,
    })
}

fn decode_optional_hex(
    value: Option<String>,
) -> Result<Option<Vec<u8>>, RemoteGatewayHttpClientError> {
    let Some(value) = value else {
        return Ok(None);
    };

    hex::decode(value.trim())
        .map(Some)
        .map_err(|error| RemoteGatewayHttpClientError::Decode(error.to_string()))
}

fn validate_base_url(base_url: &str) -> Result<(), RemoteGatewayHttpClientError> {
    let base_url = base_url.trim();

    if base_url.is_empty() {
        return Err(RemoteGatewayHttpClientError::MissingBaseUrl);
    }

    let parsed =
        reqwest::Url::parse(base_url).map_err(|_| RemoteGatewayHttpClientError::InvalidBaseUrl)?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_remote_gateway_url(&parsed) => Ok(()),
        "http" => Err(RemoteGatewayHttpClientError::InsecureRemoteGatewayUrl),
        _ => Err(RemoteGatewayHttpClientError::InvalidBaseUrl),
    }
}

fn is_loopback_remote_gateway_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };

    let host = host.trim_matches(|character| matches!(character, '[' | ']'));

    if host.eq_ignore_ascii_case("localhost") || matches!(host, "127.0.0.1" | "::1") {
        return true;
    }

    host.parse::<std::net::IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

fn action_to_wire(action: RemoteGatewayAction) -> &'static str {
    match action {
        RemoteGatewayAction::PutCiphertextObject => "put_ciphertext_object",
        RemoteGatewayAction::GetCiphertextObject => "get_ciphertext_object",
        RemoteGatewayAction::HeadCiphertextObject => "head_ciphertext_object",
        RemoteGatewayAction::ListCiphertextManifest => "list_ciphertext_manifest",
        RemoteGatewayAction::PutEncryptedManifest => "put_encrypted_manifest",
        RemoteGatewayAction::DeleteCiphertextObject => "delete_ciphertext_object",
        RemoteGatewayAction::CreateTrustlessBucket => "create_trustless_bucket",
    }
}

fn wire_to_action(action: &str) -> Result<RemoteGatewayAction, RemoteGatewayHttpClientError> {
    match action {
        "put_ciphertext_object" => Ok(RemoteGatewayAction::PutCiphertextObject),
        "get_ciphertext_object" => Ok(RemoteGatewayAction::GetCiphertextObject),
        "head_ciphertext_object" => Ok(RemoteGatewayAction::HeadCiphertextObject),
        "list_ciphertext_manifest" => Ok(RemoteGatewayAction::ListCiphertextManifest),
        "put_encrypted_manifest" => Ok(RemoteGatewayAction::PutEncryptedManifest),
        "delete_ciphertext_object" => Ok(RemoteGatewayAction::DeleteCiphertextObject),
        "create_trustless_bucket" => Ok(RemoteGatewayAction::CreateTrustlessBucket),
        unknown => Err(RemoteGatewayHttpClientError::UnknownAction(
            unknown.to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::remote_gateway::TrustlessRemoteGatewayExecutor;

    #[derive(Debug, Default)]
    struct MockState {
        seen_url: Option<String>,
        seen_body: Option<Vec<u8>>,
        seen_headers: Vec<(String, String)>,
    }

    #[derive(Debug, Clone)]
    struct MockHttpTransport {
        response: Vec<u8>,
        state: Rc<RefCell<MockState>>,
    }

    impl MockHttpTransport {
        fn new(response: RemoteGatewayHttpResponseEnvelope) -> Self {
            Self {
                response: serde_json::to_vec(&response).unwrap(),
                state: Rc::new(RefCell::new(MockState::default())),
            }
        }

        fn seen_body_json(&self) -> serde_json::Value {
            let body = self.state.borrow().seen_body.clone().unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        fn seen_headers(&self) -> Vec<(String, String)> {
            self.state.borrow().seen_headers.clone()
        }

        fn seen_header(&self, name: &str) -> Option<String> {
            self.seen_headers()
                .into_iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        }

        fn no_body_was_sent(&self) -> bool {
            self.state.borrow().seen_body.is_none()
        }
    }

    impl RemoteGatewayHttpTransport for MockHttpTransport {
        fn post_json(
            &self,
            url: &str,
            body: Vec<u8>,
            headers: Vec<(String, String)>,
        ) -> Result<Vec<u8>, RemoteGatewayHttpClientError> {
            let mut state = self.state.borrow_mut();
            state.seen_url = Some(url.to_owned());
            state.seen_body = Some(body);
            state.seen_headers = headers;
            Ok(self.response.clone())
        }
    }

    fn request(action: RemoteGatewayAction) -> CiphertextGatewayRequest {
        CiphertextGatewayRequest {
            bucket_id_hex: hex::encode([1u8; 32]),
            action,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            expected_manifest_reference_hex: None,
            plaintext_payload_present: false,
        }
    }

    fn response(action: RemoteGatewayAction) -> RemoteGatewayHttpResponseEnvelope {
        RemoteGatewayHttpResponseEnvelope {
            version: WIRE_VERSION,
            action: action_to_wire(action).to_owned(),
            ciphertext_hex: None,
            encrypted_manifest_hex: None,
            ciphertext_reference_hex: None,
            encrypted_manifest_reference_hex: None,
            metadata_only: false,
            gateway_plaintext_access: false,
        }
    }

    fn assert_remote_body_excludes_object_keys_and_ids(body: &serde_json::Value) {
        let object = body.as_object().unwrap();
        for forbidden in [
            "bucket",
            "object_key",
            "objectKey",
            "object_key_id",
            "objectKeyId",
            "caller_object_id",
            "callerSuppliedObjectId",
            "key",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "remote HTTP envelope leaked field {forbidden}"
            );
        }

        let encoded = serde_json::to_string(body).unwrap();
        for forbidden in [
            "object_key",
            "objectKey",
            "object_key_id",
            "objectKeyId",
            "caller_object_id",
            "callerSuppliedObjectId",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "remote HTTP envelope leaked token {forbidden}"
            );
        }
    }

    fn client_with_transport(
        response: RemoteGatewayHttpResponseEnvelope,
    ) -> (
        RemoteGatewayHttpClient<MockHttpTransport>,
        MockHttpTransport,
    ) {
        let transport = MockHttpTransport::new(response);
        let client = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "http://127.0.0.1:3000/".to_owned(),
                sigv4_auth: None,
            },
            transport.clone(),
        )
        .unwrap();

        (client, transport)
    }

    fn sigv4_auth() -> RemoteGatewaySigV4AuthConfig {
        RemoteGatewaySigV4AuthConfig::from_parts(
            "s3w-dev-access-key",
            "s3w-dev-secret-key",
            "us-east-1",
            "s3",
        )
        .unwrap()
    }

    fn client_with_sigv4_transport(
        response: RemoteGatewayHttpResponseEnvelope,
    ) -> (
        RemoteGatewayHttpClient<MockHttpTransport>,
        MockHttpTransport,
    ) {
        let transport = MockHttpTransport::new(response);
        let client = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "http://127.0.0.1:3000/".to_owned(),
                sigv4_auth: Some(sigv4_auth()),
            },
            transport.clone(),
        )
        .unwrap();

        (client, transport)
    }

    #[test]
    #[ignore = "requires live gateway with registered dev SigV4 identity"]
    fn live_http_client_uses_sigv4_to_put_and_get_ciphertext_object() {
        let base_url = std::env::var("TRUSTLESS_PROXY_REMOTE_GATEWAY_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned());

        let client = RemoteGatewayHttpClient::from_env(base_url).unwrap();
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let bucket_id_hex = hex::encode([std::process::id() as u8; 32]);
        let ciphertext = b"rust remote gateway http sigv4 ciphertext".to_vec();

        let mut put = request(RemoteGatewayAction::PutCiphertextObject);
        put.bucket_id_hex = bucket_id_hex.clone();
        put.ciphertext_payload = Some(ciphertext.clone());

        let put_result = executor.execute(put).unwrap();

        assert_eq!(put_result.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(put_result.metadata_only);
        assert!(!put_result.gateway_plaintext_access);
        assert!(put_result.ciphertext_payload.is_none());
        assert!(put_result.encrypted_manifest_payload.is_none());
        assert!(put_result.ciphertext_reference_hex.is_some());

        let mut get = request(RemoteGatewayAction::GetCiphertextObject);
        get.bucket_id_hex = bucket_id_hex;
        get.ciphertext_reference_hex = put_result.ciphertext_reference_hex;

        let get_result = executor.execute(get).unwrap();

        assert_eq!(get_result.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(get_result.ciphertext_payload, Some(ciphertext));
        assert!(!get_result.gateway_plaintext_access);
    }

    #[test]
    fn http_client_sends_sigv4_authorization_when_credentials_configured() {
        let (client, transport) =
            client_with_sigv4_transport(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::PutCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());

        executor.execute(request).unwrap();

        let authorization = transport.seen_header("authorization").unwrap();

        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=s3w-dev-access-key/"));
        assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert!(authorization.contains("Signature="));
        assert!(!authorization.contains("s3w-dev-secret-key"));
        assert_eq!(
            transport.seen_header("host").as_deref(),
            Some("127.0.0.1:3000")
        );
        assert!(transport.seen_header("x-amz-date").is_some());
    }

    #[test]
    fn http_client_sends_x_amz_content_sha256_matching_body() {
        let (client, transport) =
            client_with_sigv4_transport(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::PutCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());

        executor.execute(request).unwrap();

        let body = transport.state.borrow().seen_body.clone().unwrap();
        assert_eq!(
            transport.seen_header("x-amz-content-sha256").as_deref(),
            Some(sha256_hex(&body).as_str())
        );
    }

    #[test]
    fn http_client_builds_deterministic_sigv4_headers_for_live_gateway_shape() {
        let headers = build_sigv4_headers(
            &sigv4_auth(),
            "http://127.0.0.1:3000/trustless/v1/ciphertext-gateway",
            br#"{"version":1}"#,
            "20260602T150623Z",
        )
        .unwrap();

        let authorization = headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value)
            .unwrap();

        assert!(authorization
            .contains("Credential=s3w-dev-access-key/20260602/us-east-1/s3/aws4_request"));
        assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert!(authorization.contains("Signature="));
    }

    #[test]
    fn http_client_does_not_log_or_debug_secret_access_key() {
        let auth = sigv4_auth();
        let config = RemoteGatewayHttpClientConfig {
            base_url: "http://127.0.0.1:3000".to_owned(),
            sigv4_auth: Some(auth),
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("s3w-dev-access-key"));
        assert!(!debug.contains("s3w-dev-secret-key"));
    }

    #[test]
    fn http_client_rejects_empty_remote_gateway_secret_when_access_key_present() {
        let err =
            RemoteGatewaySigV4AuthConfig::from_parts("s3w-dev-access-key", "", "us-east-1", "s3")
                .unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayHttpClientError::MissingRemoteGatewaySecretAccessKey
        );
    }

    #[test]
    fn http_timeout_parser_defaults_or_accepts_positive_seconds() {
        assert_eq!(
            parse_remote_gateway_http_timeout_secs(None),
            Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS)
        );
        assert_eq!(
            parse_remote_gateway_http_timeout_secs(Some("   ")),
            Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS)
        );
        assert_eq!(
            parse_remote_gateway_http_timeout_secs(Some("0")),
            Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS)
        );
        assert_eq!(
            parse_remote_gateway_http_timeout_secs(Some("not-a-number")),
            Duration::from_secs(DEFAULT_REMOTE_GATEWAY_HTTP_TIMEOUT_SECS)
        );
        assert_eq!(
            parse_remote_gateway_http_timeout_secs(Some("5")),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn http_client_sends_put_ciphertext_json_without_plaintext() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::PutCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());

        let response = executor.execute(request).unwrap();

        assert_eq!(response.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!response.gateway_plaintext_access);

        let body = transport.seen_body_json();

        assert_remote_body_excludes_object_keys_and_ids(&body);
        assert_eq!(body["version"], WIRE_VERSION);
        assert_eq!(body["action"], "put_ciphertext_object");
        assert_eq!(body["bucket_id_hex"], hex::encode([1u8; 32]));
        assert_eq!(body["ciphertext_hex"], hex::encode(b"ciphertext"));
        assert!(body["ciphertext_reference_hex"].is_null());
        assert!(body["expected_manifest_reference_hex"].is_null());
        assert!(body.get("plaintext_payload").is_none());
        assert!(body.get("plaintext_body").is_none());
    }

    #[test]
    fn http_client_fetches_get_ciphertext_response() {
        let mut response = response(RemoteGatewayAction::GetCiphertextObject);
        response.ciphertext_hex = Some(hex::encode(b"ciphertext"));
        response.ciphertext_reference_hex = Some("ab".repeat(32));

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        let result = executor.execute(request).unwrap();

        assert_eq!(result.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(result.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert_eq!(result.ciphertext_reference_hex, Some("ab".repeat(32)));
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn http_client_fetches_encrypted_manifest_response() {
        let mut response = response(RemoteGatewayAction::ListCiphertextManifest);
        response.encrypted_manifest_hex = Some(hex::encode(b"encrypted-manifest"));
        response.encrypted_manifest_reference_hex = Some("cd".repeat(32));
        response.metadata_only = true;

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let result = executor
            .execute(request(RemoteGatewayAction::ListCiphertextManifest))
            .unwrap();

        assert_eq!(result.action, RemoteGatewayAction::ListCiphertextManifest);
        assert_eq!(
            result.encrypted_manifest_payload,
            Some(b"encrypted-manifest".to_vec())
        );
        assert_eq!(
            result.encrypted_manifest_reference_hex,
            Some("cd".repeat(32))
        );
        assert!(result.metadata_only);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn http_client_sends_direct_ciphertext_reference_for_read() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::GetCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        executor.execute(request).unwrap();

        let body = transport.seen_body_json();

        assert_remote_body_excludes_object_keys_and_ids(&body);
        assert_eq!(body["action"], "get_ciphertext_object");
        assert_eq!(body["ciphertext_reference_hex"], "ab".repeat(32));
        assert!(body["expected_manifest_reference_hex"].is_null());
        assert!(body["ciphertext_hex"].is_null());
        assert!(body["encrypted_manifest_hex"].is_null());
    }

    #[test]
    fn http_client_requires_ciphertext_reference_for_read_before_transport() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::GetCiphertextObject));

        let err = client
            .execute_ciphertext_request(request(RemoteGatewayAction::GetCiphertextObject))
            .unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::MissingCiphertextReference);
        assert!(transport.no_body_was_sent());

        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::HeadCiphertextObject));
        let mut request = request(RemoteGatewayAction::HeadCiphertextObject);
        request.ciphertext_reference_hex = Some(" ".to_owned());

        let err = client.execute_ciphertext_request(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::MissingCiphertextReference);
        assert!(transport.no_body_was_sent());
    }

    #[test]
    fn http_client_rejects_missing_or_malformed_bucket_id_before_transport() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::GetCiphertextObject));

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.bucket_id_hex = " ".to_owned();
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        let err = client.execute_ciphertext_request(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::MissingBucketId);
        assert!(transport.no_body_was_sent());

        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::GetCiphertextObject));

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.bucket_id_hex = "not-hex".to_owned();
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        let err = client.execute_ciphertext_request(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::InvalidBucketId);
        assert!(transport.no_body_was_sent());
    }

    #[test]
    fn http_client_sends_put_encrypted_manifest_without_plaintext() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::PutEncryptedManifest));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::PutEncryptedManifest);
        request.encrypted_manifest_payload = Some(b"encrypted-manifest".to_vec());
        request.expected_manifest_reference_hex = Some("ef".repeat(32));

        let result = executor.execute(request).unwrap();

        assert_eq!(result.action, RemoteGatewayAction::PutEncryptedManifest);

        let body = transport.seen_body_json();

        assert_remote_body_excludes_object_keys_and_ids(&body);
        assert_eq!(body["action"], "put_encrypted_manifest");
        assert_eq!(
            body["encrypted_manifest_hex"],
            hex::encode(b"encrypted-manifest")
        );
        assert_eq!(body["expected_manifest_reference_hex"], "ef".repeat(32));
        assert!(body["ciphertext_hex"].is_null());
        assert!(body["ciphertext_reference_hex"].is_null());
        assert!(body.get("plaintext_payload").is_none());
        assert!(body.get("plaintext_body").is_none());
    }

    #[test]
    fn http_client_sends_delete_encrypted_manifest_only() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::DeleteCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::DeleteCiphertextObject);
        request.encrypted_manifest_payload = Some(b"encrypted-manifest".to_vec());
        request.expected_manifest_reference_hex = Some("12".repeat(32));

        let result = executor.execute(request).unwrap();

        assert_eq!(result.action, RemoteGatewayAction::DeleteCiphertextObject);

        let body = transport.seen_body_json();

        assert_remote_body_excludes_object_keys_and_ids(&body);
        assert_eq!(body["action"], "delete_ciphertext_object");
        assert_eq!(
            body["encrypted_manifest_hex"],
            hex::encode(b"encrypted-manifest")
        );
        assert_eq!(body["expected_manifest_reference_hex"], "12".repeat(32));
        assert!(body["ciphertext_hex"].is_null());
        assert!(body["ciphertext_reference_hex"].is_null());
        assert!(body.get("plaintext_payload").is_none());
    }

    #[test]
    fn http_client_requires_delete_expected_manifest_reference_before_transport() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::DeleteCiphertextObject));

        let mut request = request(RemoteGatewayAction::DeleteCiphertextObject);
        request.encrypted_manifest_payload = Some(b"encrypted-manifest".to_vec());

        let err = client.execute_ciphertext_request(request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::MissingExpectedManifestReference
        );
        assert!(transport.no_body_was_sent());
    }

    #[test]
    fn http_client_rejects_references_on_wrong_actions_before_transport() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut put_request = request(RemoteGatewayAction::PutCiphertextObject);
        put_request.ciphertext_payload = Some(b"ciphertext".to_vec());
        put_request.ciphertext_reference_hex = Some("ab".repeat(32));

        let err = executor.execute(put_request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::UnexpectedCiphertextReference(
                RemoteGatewayAction::PutCiphertextObject
            )
        );
        assert!(transport.no_body_was_sent());

        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::GetCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut get_request = request(RemoteGatewayAction::GetCiphertextObject);
        get_request.expected_manifest_reference_hex = Some("cd".repeat(32));

        let err = executor.execute(get_request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::UnexpectedExpectedManifestReference(
                RemoteGatewayAction::GetCiphertextObject
            )
        );
        assert!(transport.no_body_was_sent());
    }

    #[test]
    fn http_client_rejects_plaintext_payload_before_transport() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::PutCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::PutCiphertextObject);
        request.ciphertext_payload = Some(b"ciphertext".to_vec());
        request.plaintext_payload_present = true;

        let err = executor.execute(request).unwrap_err();

        assert_eq!(err, RemoteGatewayClientError::PlaintextPayloadRejected);
        assert!(transport.no_body_was_sent());
    }

    #[test]
    fn http_client_rejects_response_claiming_gateway_plaintext_access() {
        let mut response = response(RemoteGatewayAction::GetCiphertextObject);
        response.gateway_plaintext_access = true;

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        let err = executor.execute(request).unwrap_err();

        assert_eq!(
            err,
            RemoteGatewayClientError::GatewayPlaintextAccessRejected
        );
    }

    #[test]
    fn http_client_rejects_invalid_base_url() {
        let transport = MockHttpTransport::new(response(RemoteGatewayAction::GetCiphertextObject));

        let err = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: " ".to_owned(),
                sigv4_auth: None,
            },
            transport.clone(),
        )
        .unwrap_err();

        assert_eq!(err, RemoteGatewayHttpClientError::MissingBaseUrl);

        let err = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "127.0.0.1:3000".to_owned(),
                sigv4_auth: None,
            },
            transport,
        )
        .unwrap_err();

        assert_eq!(err, RemoteGatewayHttpClientError::InvalidBaseUrl);
    }

    #[test]
    fn http_client_rejects_non_loopback_http_base_url() {
        let transport = MockHttpTransport::new(response(RemoteGatewayAction::GetCiphertextObject));

        let err = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "http://gateway.local".to_owned(),
                sigv4_auth: None,
            },
            transport,
        )
        .unwrap_err();

        assert_eq!(err, RemoteGatewayHttpClientError::InsecureRemoteGatewayUrl);
    }

    #[test]
    fn http_client_accepts_loopback_http_base_url_for_dev() {
        for base_url in [
            "http://127.0.0.1:3000",
            "http://localhost:3000",
            "http://[::1]:3000",
        ] {
            let transport =
                MockHttpTransport::new(response(RemoteGatewayAction::GetCiphertextObject));

            RemoteGatewayHttpClient::with_transport(
                RemoteGatewayHttpClientConfig {
                    base_url: base_url.to_owned(),
                    sigv4_auth: None,
                },
                transport,
            )
            .unwrap();
        }
    }

    #[test]
    fn http_client_accepts_https_base_url() {
        let transport = MockHttpTransport::new(response(RemoteGatewayAction::GetCiphertextObject));

        RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "https://gateway.local".to_owned(),
                sigv4_auth: None,
            },
            transport,
        )
        .unwrap();
    }

    #[test]
    fn http_client_rejects_unknown_response_action() {
        let mut response = response(RemoteGatewayAction::GetCiphertextObject);
        response.action = "unknown-action".to_owned();

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::GetCiphertextObject);
        request.ciphertext_reference_hex = Some("ab".repeat(32));

        let err = executor.execute(request).unwrap_err();

        assert!(matches!(err, RemoteGatewayClientError::Http(_)));
    }

    #[test]
    fn http_client_wire_contract_matches_gateway_ciphertext_endpoint_for_all_actions() {
        let cases = vec![
            (
                RemoteGatewayAction::PutCiphertextObject,
                "put_ciphertext_object",
                Some(b"ciphertext-object".to_vec()),
                None,
                None,
                None,
                true,
            ),
            (
                RemoteGatewayAction::GetCiphertextObject,
                "get_ciphertext_object",
                None,
                None,
                Some(b"ciphertext-object".to_vec()),
                None,
                false,
            ),
            (
                RemoteGatewayAction::HeadCiphertextObject,
                "head_ciphertext_object",
                None,
                None,
                None,
                None,
                true,
            ),
            (
                RemoteGatewayAction::ListCiphertextManifest,
                "list_ciphertext_manifest",
                None,
                None,
                None,
                Some(b"encrypted-manifest".to_vec()),
                false,
            ),
            (
                RemoteGatewayAction::PutEncryptedManifest,
                "put_encrypted_manifest",
                None,
                Some(b"encrypted-manifest".to_vec()),
                None,
                None,
                true,
            ),
            (
                RemoteGatewayAction::DeleteCiphertextObject,
                "delete_ciphertext_object",
                None,
                Some(b"encrypted-manifest".to_vec()),
                None,
                None,
                true,
            ),
            (
                RemoteGatewayAction::CreateTrustlessBucket,
                "create_trustless_bucket",
                None,
                None,
                None,
                None,
                true,
            ),
        ];

        for (
            action,
            expected_wire_action,
            ciphertext_payload,
            encrypted_manifest_payload,
            response_ciphertext_payload,
            response_encrypted_manifest_payload,
            response_metadata_only,
        ) in cases
        {
            let request_ciphertext_reference_hex = matches!(
                action,
                RemoteGatewayAction::GetCiphertextObject
                    | RemoteGatewayAction::HeadCiphertextObject
            )
            .then(|| "ab".repeat(32));
            let request_expected_manifest_reference_hex = matches!(
                action,
                RemoteGatewayAction::PutEncryptedManifest
                    | RemoteGatewayAction::DeleteCiphertextObject
            )
            .then(|| "cd".repeat(32));
            let response_ciphertext_reference_hex = matches!(
                action,
                RemoteGatewayAction::PutCiphertextObject
                    | RemoteGatewayAction::GetCiphertextObject
                    | RemoteGatewayAction::HeadCiphertextObject
            )
            .then(|| "ef".repeat(32));
            let response_encrypted_manifest_reference_hex = matches!(
                action,
                RemoteGatewayAction::ListCiphertextManifest
                    | RemoteGatewayAction::PutEncryptedManifest
                    | RemoteGatewayAction::DeleteCiphertextObject
            )
            .then(|| "12".repeat(32));

            let transport = MockHttpTransport::new(RemoteGatewayHttpResponseEnvelope {
                version: WIRE_VERSION,
                action: expected_wire_action.to_owned(),
                ciphertext_hex: response_ciphertext_payload.as_ref().map(hex::encode),
                encrypted_manifest_hex: response_encrypted_manifest_payload
                    .as_ref()
                    .map(hex::encode),
                ciphertext_reference_hex: response_ciphertext_reference_hex.clone(),
                encrypted_manifest_reference_hex: response_encrypted_manifest_reference_hex.clone(),
                metadata_only: response_metadata_only,
                gateway_plaintext_access: false,
            });

            let client = RemoteGatewayHttpClient::with_transport(
                RemoteGatewayHttpClientConfig {
                    base_url: "https://gateway.local/".to_owned(),
                    sigv4_auth: None,
                },
                transport.clone(),
            )
            .unwrap();

            let response = client
                .execute_ciphertext_request(CiphertextGatewayRequest {
                    bucket_id_hex: hex::encode([3u8; 32]),
                    action,
                    ciphertext_payload: ciphertext_payload.clone(),
                    encrypted_manifest_payload: encrypted_manifest_payload.clone(),
                    ciphertext_reference_hex: request_ciphertext_reference_hex.clone(),
                    expected_manifest_reference_hex: request_expected_manifest_reference_hex
                        .clone(),
                    plaintext_payload_present: false,
                })
                .unwrap();

            assert_eq!(
                transport.state.borrow().seen_url.as_deref(),
                Some("https://gateway.local/trustless/v1/ciphertext-gateway")
            );

            let body = transport.seen_body_json();
            let object = body.as_object().unwrap();

            assert_remote_body_excludes_object_keys_and_ids(&body);
            assert_eq!(object.len(), 7);
            assert!(object.contains_key("version"));
            assert!(object.contains_key("action"));
            assert!(object.contains_key("bucket_id_hex"));
            assert!(object.contains_key("ciphertext_hex"));
            assert!(object.contains_key("encrypted_manifest_hex"));
            assert!(object.contains_key("ciphertext_reference_hex"));
            assert!(object.contains_key("expected_manifest_reference_hex"));

            assert_eq!(body["version"], WIRE_VERSION);
            assert_eq!(body["action"], expected_wire_action);
            assert_eq!(body["bucket_id_hex"], hex::encode([3u8; 32]));

            match ciphertext_payload {
                Some(expected_payload) => {
                    assert_eq!(body["ciphertext_hex"], hex::encode(expected_payload));
                }
                None => assert!(body["ciphertext_hex"].is_null()),
            }

            match encrypted_manifest_payload {
                Some(expected_payload) => {
                    assert_eq!(
                        body["encrypted_manifest_hex"],
                        hex::encode(expected_payload)
                    );
                }
                None => assert!(body["encrypted_manifest_hex"].is_null()),
            }

            match request_ciphertext_reference_hex {
                Some(expected_reference) => {
                    assert_eq!(body["ciphertext_reference_hex"], expected_reference);
                }
                None => assert!(body["ciphertext_reference_hex"].is_null()),
            }

            match request_expected_manifest_reference_hex {
                Some(expected_reference) => {
                    assert_eq!(body["expected_manifest_reference_hex"], expected_reference);
                }
                None => assert!(body["expected_manifest_reference_hex"].is_null()),
            }

            assert_eq!(response.action, action);
            assert_eq!(response.ciphertext_payload, response_ciphertext_payload);
            assert_eq!(
                response.encrypted_manifest_payload,
                response_encrypted_manifest_payload
            );
            assert_eq!(
                response.ciphertext_reference_hex,
                response_ciphertext_reference_hex
            );
            assert_eq!(
                response.encrypted_manifest_reference_hex,
                response_encrypted_manifest_reference_hex
            );
            assert_eq!(response.metadata_only, response_metadata_only);
            assert!(!response.gateway_plaintext_access);
        }
    }
}
