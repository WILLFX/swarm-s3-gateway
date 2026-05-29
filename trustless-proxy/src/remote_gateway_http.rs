use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
use crate::planner::RemoteGatewayAction;
use crate::remote_gateway::{RemoteGatewayClientError, TrustlessRemoteGatewayClient};

const CIPHERTEXT_GATEWAY_PATH: &str = "/trustless/v1/ciphertext-gateway";
const WIRE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteGatewayHttpClientConfig {
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteGatewayHttpRequestEnvelope {
    version: u32,
    action: String,
    bucket: String,
    key: Option<String>,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteGatewayHttpResponseEnvelope {
    version: u32,
    action: String,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    metadata_only: bool,
    gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteGatewayHttpClientError {
    #[error("remote gateway base URL is required")]
    MissingBaseUrl,

    #[error("remote gateway base URL must start with http:// or https://")]
    InvalidBaseUrl,

    #[error("plaintext payload must never be sent to the remote gateway")]
    PlaintextPayloadRejected,

    #[error("ciphertext payload is required for PUT ciphertext object")]
    MissingCiphertextPayload,

    #[error("encrypted manifest payload is required for DELETE ciphertext object")]
    MissingEncryptedManifestPayload,

    #[error("request action does not allow ciphertext payload: {0:?}")]
    UnexpectedCiphertextPayload(RemoteGatewayAction),

    #[error("request action does not allow encrypted manifest payload: {0:?}")]
    UnexpectedEncryptedManifestPayload(RemoteGatewayAction),

    #[error("unknown remote gateway HTTP action: {0}")]
    UnknownAction(String),

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
            RemoteGatewayHttpClientError::PlaintextPayloadRejected => {
                RemoteGatewayClientError::PlaintextPayloadRejected
            }
            RemoteGatewayHttpClientError::MissingCiphertextPayload => {
                RemoteGatewayClientError::MissingPutCiphertextPayload
            }
            RemoteGatewayHttpClientError::MissingEncryptedManifestPayload => {
                RemoteGatewayClientError::MissingDeleteEncryptedManifestPayload
            }
            RemoteGatewayHttpClientError::UnexpectedCiphertextPayload(action) => {
                RemoteGatewayClientError::UnexpectedCiphertextPayload(action)
            }
            RemoteGatewayHttpClientError::UnexpectedEncryptedManifestPayload(action) => {
                RemoteGatewayClientError::UnexpectedEncryptedManifestPayload(action)
            }
            RemoteGatewayHttpClientError::GatewayPlaintextAccessRejected => {
                RemoteGatewayClientError::GatewayPlaintextAccessRejected
            }
            other => RemoteGatewayClientError::Http(other.to_string()),
        }
    }
}

pub trait RemoteGatewayHttpTransport {
    fn post_json(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RemoteGatewayHttpClientError>;
}

#[derive(Debug, Clone)]
pub struct ReqwestRemoteGatewayHttpTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestRemoteGatewayHttpTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl Default for ReqwestRemoteGatewayHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteGatewayHttpTransport for ReqwestRemoteGatewayHttpTransport {
    fn post_json(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, RemoteGatewayHttpClientError> {
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
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

        let response_body = self
            .transport
            .post_json(&self.endpoint_url(), body)
            .map_err(RemoteGatewayClientError::from)?;

        let response_envelope: RemoteGatewayHttpResponseEnvelope =
            serde_json::from_slice(&response_body)
                .map_err(|error| RemoteGatewayClientError::Http(error.to_string()))?;

        http_envelope_to_response(response_envelope).map_err(RemoteGatewayClientError::from)
    }
}

fn request_to_http_envelope(
    request: CiphertextGatewayRequest,
) -> Result<RemoteGatewayHttpRequestEnvelope, RemoteGatewayHttpClientError> {
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
        }
        RemoteGatewayAction::DeleteCiphertextObject => {
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
        }
        RemoteGatewayAction::GetCiphertextObject
        | RemoteGatewayAction::HeadCiphertextObject
        | RemoteGatewayAction::ListCiphertextManifest
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
        }
    }

    Ok(RemoteGatewayHttpRequestEnvelope {
        version: WIRE_VERSION,
        action: action_to_wire(request.action).to_owned(),
        bucket: request.bucket,
        key: request.key,
        ciphertext_hex: request.ciphertext_payload.map(hex::encode),
        encrypted_manifest_hex: request.encrypted_manifest_payload.map(hex::encode),
    })
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

    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return Err(RemoteGatewayHttpClientError::InvalidBaseUrl);
    }

    Ok(())
}

fn action_to_wire(action: RemoteGatewayAction) -> &'static str {
    match action {
        RemoteGatewayAction::PutCiphertextObject => "put_ciphertext_object",
        RemoteGatewayAction::GetCiphertextObject => "get_ciphertext_object",
        RemoteGatewayAction::HeadCiphertextObject => "head_ciphertext_object",
        RemoteGatewayAction::ListCiphertextManifest => "list_ciphertext_manifest",
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

        fn no_body_was_sent(&self) -> bool {
            self.state.borrow().seen_body.is_none()
        }
    }

    impl RemoteGatewayHttpTransport for MockHttpTransport {
        fn post_json(
            &self,
            url: &str,
            body: Vec<u8>,
        ) -> Result<Vec<u8>, RemoteGatewayHttpClientError> {
            let mut state = self.state.borrow_mut();
            state.seen_url = Some(url.to_owned());
            state.seen_body = Some(body);
            Ok(self.response.clone())
        }
    }

    fn request(action: RemoteGatewayAction) -> CiphertextGatewayRequest {
        CiphertextGatewayRequest {
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            action,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        }
    }

    fn response(action: RemoteGatewayAction) -> RemoteGatewayHttpResponseEnvelope {
        RemoteGatewayHttpResponseEnvelope {
            version: WIRE_VERSION,
            action: action_to_wire(action).to_owned(),
            ciphertext_hex: None,
            encrypted_manifest_hex: None,
            metadata_only: false,
            gateway_plaintext_access: false,
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
            },
            transport.clone(),
        )
        .unwrap();

        (client, transport)
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

        assert_eq!(body["version"], WIRE_VERSION);
        assert_eq!(body["action"], "put_ciphertext_object");
        assert_eq!(body["bucket"], "bucket");
        assert_eq!(body["key"], "secret.txt");
        assert_eq!(body["ciphertext_hex"], hex::encode(b"ciphertext"));
        assert!(body.get("plaintext_payload").is_none());
        assert!(body.get("plaintext_body").is_none());
    }

    #[test]
    fn http_client_fetches_get_ciphertext_response() {
        let mut response = response(RemoteGatewayAction::GetCiphertextObject);
        response.ciphertext_hex = Some(hex::encode(b"ciphertext"));

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let result = executor
            .execute(request(RemoteGatewayAction::GetCiphertextObject))
            .unwrap();

        assert_eq!(result.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(result.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn http_client_fetches_encrypted_manifest_response() {
        let mut response = response(RemoteGatewayAction::ListCiphertextManifest);
        response.encrypted_manifest_hex = Some(hex::encode(b"encrypted-manifest"));
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
        assert!(result.metadata_only);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn http_client_sends_delete_encrypted_manifest_only() {
        let (client, transport) =
            client_with_transport(response(RemoteGatewayAction::DeleteCiphertextObject));
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let mut request = request(RemoteGatewayAction::DeleteCiphertextObject);
        request.encrypted_manifest_payload = Some(b"encrypted-manifest".to_vec());

        let result = executor.execute(request).unwrap();

        assert_eq!(result.action, RemoteGatewayAction::DeleteCiphertextObject);

        let body = transport.seen_body_json();

        assert_eq!(body["action"], "delete_ciphertext_object");
        assert_eq!(
            body["encrypted_manifest_hex"],
            hex::encode(b"encrypted-manifest")
        );
        assert!(body["ciphertext_hex"].is_null());
        assert!(body.get("plaintext_payload").is_none());
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

        let err = executor
            .execute(request(RemoteGatewayAction::GetCiphertextObject))
            .unwrap_err();

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
            },
            transport.clone(),
        )
        .unwrap_err();

        assert_eq!(err, RemoteGatewayHttpClientError::MissingBaseUrl);

        let err = RemoteGatewayHttpClient::with_transport(
            RemoteGatewayHttpClientConfig {
                base_url: "127.0.0.1:3000".to_owned(),
            },
            transport,
        )
        .unwrap_err();

        assert_eq!(err, RemoteGatewayHttpClientError::InvalidBaseUrl);
    }

    #[test]
    fn http_client_rejects_unknown_response_action() {
        let mut response = response(RemoteGatewayAction::GetCiphertextObject);
        response.action = "unknown-action".to_owned();

        let (client, _transport) = client_with_transport(response);
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        let err = executor
            .execute(request(RemoteGatewayAction::GetCiphertextObject))
            .unwrap_err();

        assert!(matches!(err, RemoteGatewayClientError::Http(_)));
    }
}
