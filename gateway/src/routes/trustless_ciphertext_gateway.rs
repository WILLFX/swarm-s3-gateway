use crate::{
    app_state::AppState,
    bee::client::{BeeClient, BeeStorage},
};
use axum::{Json, extract::State, http::StatusCode};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

const WIRE_VERSION: u32 = 1;
const TRUSTLESS_MANIFEST_KEY: &str = "__s3w_trustless_manifest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CiphertextGatewayAction {
    PutCiphertextObject,
    GetCiphertextObject,
    HeadCiphertextObject,
    ListCiphertextManifest,
    PutEncryptedManifest,
    DeleteCiphertextObject,
    CreateTrustlessBucket,
}

impl CiphertextGatewayAction {
    fn parse(value: &str) -> Result<Self, RouteError> {
        match value {
            "put_ciphertext_object" => Ok(Self::PutCiphertextObject),
            "get_ciphertext_object" => Ok(Self::GetCiphertextObject),
            "head_ciphertext_object" => Ok(Self::HeadCiphertextObject),
            "list_ciphertext_manifest" => Ok(Self::ListCiphertextManifest),
            "put_encrypted_manifest" => Ok(Self::PutEncryptedManifest),
            "delete_ciphertext_object" => Ok(Self::DeleteCiphertextObject),
            "create_trustless_bucket" => Ok(Self::CreateTrustlessBucket),
            _ => Err(RouteError::bad_request(
                "unsupported ciphertext gateway action",
            )),
        }
    }

    fn as_wire_str(self) -> &'static str {
        match self {
            Self::PutCiphertextObject => "put_ciphertext_object",
            Self::GetCiphertextObject => "get_ciphertext_object",
            Self::HeadCiphertextObject => "head_ciphertext_object",
            Self::ListCiphertextManifest => "list_ciphertext_manifest",
            Self::PutEncryptedManifest => "put_encrypted_manifest",
            Self::DeleteCiphertextObject => "delete_ciphertext_object",
            Self::CreateTrustlessBucket => "create_trustless_bucket",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CiphertextGatewayRequest {
    version: u32,
    action: String,
    bucket: String,
    key: Option<String>,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    #[serde(default)]
    metadata_only: Option<bool>,
    #[serde(default)]
    gateway_plaintext_access: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiphertextGatewayResponse {
    version: u32,
    action: String,
    ciphertext_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    metadata_only: bool,
    gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteError {
    status: StatusCode,
    message: &'static str,
}

impl RouteError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    fn storage_failure() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "ciphertext storage operation failed",
        }
    }

    fn into_response(self) -> (StatusCode, String) {
        (self.status, self.message.to_string())
    }
}

pub async fn handle(
    State(state): State<AppState>,
    Json(request): Json<CiphertextGatewayRequest>,
) -> Result<Json<CiphertextGatewayResponse>, (StatusCode, String)> {
    execute_ciphertext_gateway_request(state.bee_client.as_ref(), request)
        .await
        .map(Json)
}

async fn execute_ciphertext_gateway_request(
    bee_client: &dyn BeeStorage,
    request: CiphertextGatewayRequest,
) -> Result<CiphertextGatewayResponse, (StatusCode, String)> {
    validate_common_request(&request).map_err(RouteError::into_response)?;

    let action = CiphertextGatewayAction::parse(request.action.as_str())
        .map_err(RouteError::into_response)?;

    match action {
        CiphertextGatewayAction::PutCiphertextObject => {
            let key = required_key(&request).map_err(RouteError::into_response)?;
            reject_manifest_payload(&request).map_err(RouteError::into_response)?;
            let ciphertext =
                decode_required_hex(request.ciphertext_hex.as_deref(), "ciphertext_hex")
                    .map_err(RouteError::into_response)?;

            bee_client
                .put_object_and_update_pointer(&request.bucket, key, Bytes::from(ciphertext))
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?;

            Ok(metadata_response(action))
        }
        CiphertextGatewayAction::GetCiphertextObject => {
            let key = required_key(&request).map_err(RouteError::into_response)?;
            reject_all_payloads(&request).map_err(RouteError::into_response)?;

            let topic = BeeClient::derive_topic(&request.bucket, key);
            let ciphertext = bee_client
                .get_pointer_bytes(topic)
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?
                .ok_or_else(|| {
                    RouteError::not_found("ciphertext object was not found").into_response()
                })?;

            Ok(CiphertextGatewayResponse {
                version: WIRE_VERSION,
                action: action.as_wire_str().to_string(),
                ciphertext_hex: Some(hex::encode(ciphertext)),
                encrypted_manifest_hex: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            })
        }
        CiphertextGatewayAction::HeadCiphertextObject => {
            let key = required_key(&request).map_err(RouteError::into_response)?;
            reject_all_payloads(&request).map_err(RouteError::into_response)?;

            let topic = BeeClient::derive_topic(&request.bucket, key);
            bee_client
                .get_pointer_bytes(topic)
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?
                .ok_or_else(|| {
                    RouteError::not_found("ciphertext object was not found").into_response()
                })?;

            Ok(metadata_response(action))
        }
        CiphertextGatewayAction::ListCiphertextManifest => {
            reject_key(&request).map_err(RouteError::into_response)?;
            reject_all_payloads(&request).map_err(RouteError::into_response)?;

            let topic = BeeClient::derive_topic(&request.bucket, TRUSTLESS_MANIFEST_KEY);
            let encrypted_manifest = bee_client
                .get_pointer_bytes(topic)
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?
                .ok_or_else(|| {
                    RouteError::not_found("encrypted manifest was not found").into_response()
                })?;

            Ok(CiphertextGatewayResponse {
                version: WIRE_VERSION,
                action: action.as_wire_str().to_string(),
                ciphertext_hex: None,
                encrypted_manifest_hex: Some(hex::encode(encrypted_manifest)),
                metadata_only: false,
                gateway_plaintext_access: false,
            })
        }
        CiphertextGatewayAction::PutEncryptedManifest => {
            reject_key(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_payload(&request).map_err(RouteError::into_response)?;
            let encrypted_manifest = decode_required_hex(
                request.encrypted_manifest_hex.as_deref(),
                "encrypted_manifest_hex",
            )
            .map_err(RouteError::into_response)?;

            bee_client
                .put_object_and_update_pointer(
                    &request.bucket,
                    TRUSTLESS_MANIFEST_KEY,
                    Bytes::from(encrypted_manifest),
                )
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?;

            Ok(metadata_response(action))
        }
        CiphertextGatewayAction::DeleteCiphertextObject => {
            reject_key(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_payload(&request).map_err(RouteError::into_response)?;
            let encrypted_manifest = decode_required_hex(
                request.encrypted_manifest_hex.as_deref(),
                "encrypted_manifest_hex",
            )
            .map_err(RouteError::into_response)?;

            bee_client
                .put_object_and_update_pointer(
                    &request.bucket,
                    TRUSTLESS_MANIFEST_KEY,
                    Bytes::from(encrypted_manifest),
                )
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?;

            Ok(metadata_response(action))
        }
        CiphertextGatewayAction::CreateTrustlessBucket => {
            reject_key(&request).map_err(RouteError::into_response)?;
            reject_all_payloads(&request).map_err(RouteError::into_response)?;

            Ok(metadata_response(action))
        }
    }
}

fn metadata_response(action: CiphertextGatewayAction) -> CiphertextGatewayResponse {
    CiphertextGatewayResponse {
        version: WIRE_VERSION,
        action: action.as_wire_str().to_string(),
        ciphertext_hex: None,
        encrypted_manifest_hex: None,
        metadata_only: true,
        gateway_plaintext_access: false,
    }
}

fn validate_common_request(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    if request.version != WIRE_VERSION {
        return Err(RouteError::bad_request(
            "unsupported ciphertext gateway wire version",
        ));
    }

    if request.bucket.trim().is_empty() {
        return Err(RouteError::bad_request("bucket is required"));
    }

    if request.gateway_plaintext_access.unwrap_or(false) {
        return Err(RouteError::bad_request(
            "gateway plaintext access is forbidden for trustless requests",
        ));
    }

    if request.metadata_only.unwrap_or(false)
        && (request.ciphertext_hex.is_some() || request.encrypted_manifest_hex.is_some())
    {
        return Err(RouteError::bad_request(
            "metadata-only request cannot include ciphertext payloads",
        ));
    }

    Ok(())
}

fn required_key(request: &CiphertextGatewayRequest) -> Result<&str, RouteError> {
    request
        .key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| RouteError::bad_request("object key is required"))
}

fn reject_key(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    if request
        .key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .is_some()
    {
        return Err(RouteError::bad_request(
            "object key is not allowed for this action",
        ));
    }

    Ok(())
}

fn reject_ciphertext_payload(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    if request.ciphertext_hex.is_some() {
        return Err(RouteError::bad_request(
            "ciphertext object payload is not allowed for this action",
        ));
    }

    Ok(())
}

fn reject_manifest_payload(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    if request.encrypted_manifest_hex.is_some() {
        return Err(RouteError::bad_request(
            "encrypted manifest payload is not allowed for this action",
        ));
    }

    Ok(())
}

fn reject_all_payloads(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    reject_ciphertext_payload(request)?;
    reject_manifest_payload(request)?;
    Ok(())
}

fn decode_required_hex(
    value: Option<&str>,
    field_name: &'static str,
) -> Result<Vec<u8>, RouteError> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RouteError::bad_request(required_hex_message(field_name)))?;

    if value.len() % 2 != 0 {
        return Err(RouteError::bad_request(invalid_hex_message(field_name)));
    }

    let decoded =
        hex::decode(value).map_err(|_| RouteError::bad_request(invalid_hex_message(field_name)))?;

    if decoded.is_empty() {
        return Err(RouteError::bad_request(required_hex_message(field_name)));
    }

    Ok(decoded)
}

fn required_hex_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_hex" => "ciphertext_hex is required",
        "encrypted_manifest_hex" => "encrypted_manifest_hex is required",
        _ => "required hex payload is missing",
    }
}

fn invalid_hex_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_hex" => "ciphertext_hex must be valid hex",
        "encrypted_manifest_hex" => "encrypted_manifest_hex must be valid hex",
        _ => "hex payload must be valid hex",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str) -> CiphertextGatewayRequest {
        CiphertextGatewayRequest {
            version: WIRE_VERSION,
            action: action.to_string(),
            bucket: "bucket-a".to_string(),
            key: None,
            ciphertext_hex: None,
            encrypted_manifest_hex: None,
            metadata_only: None,
            gateway_plaintext_access: None,
        }
    }

    #[test]
    fn rejects_gateway_plaintext_access_flag() {
        let mut request = request("get_ciphertext_object");
        request.gateway_plaintext_access = Some(true);

        let error = validate_common_request(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            error.message,
            "gateway plaintext access is forbidden for trustless requests"
        );
    }

    #[test]
    fn rejects_unsupported_wire_version() {
        let mut request = request("get_ciphertext_object");
        request.version = WIRE_VERSION + 1;

        let error = validate_common_request(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "unsupported ciphertext gateway wire version");
    }

    #[test]
    fn rejects_unknown_action() {
        let error = CiphertextGatewayAction::parse("unsupported_remote_action").unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "unsupported ciphertext gateway action");
    }

    #[test]
    fn put_requires_object_key() {
        let request = request("put_ciphertext_object");

        let error = required_key(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "object key is required");
    }

    #[test]
    fn list_rejects_object_key() {
        let mut request = request("list_ciphertext_manifest");
        request.key = Some("private/object.txt".to_string());

        let error = reject_key(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "object key is not allowed for this action");
    }

    #[test]
    fn get_rejects_any_payload() {
        let mut request = request("get_ciphertext_object");
        request.ciphertext_hex = Some("abcd".to_string());

        let error = reject_all_payloads(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            error.message,
            "ciphertext object payload is not allowed for this action"
        );
    }

    #[test]
    fn put_decodes_ciphertext_hex() {
        let decoded = decode_required_hex(Some("68656c6c6f"), "ciphertext_hex").unwrap();

        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn put_rejects_invalid_ciphertext_hex() {
        let error = decode_required_hex(Some("not-hex"), "ciphertext_hex").unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "ciphertext_hex must be valid hex");
    }

    #[test]
    fn gateway_endpoint_decodes_put_encrypted_manifest_request() {
        let mut request = request("put_encrypted_manifest");
        request.encrypted_manifest_hex = Some(hex::encode(b"encrypted-manifest"));

        let action = CiphertextGatewayAction::parse(&request.action).unwrap();
        assert_eq!(action, CiphertextGatewayAction::PutEncryptedManifest);

        reject_key(&request).unwrap();
        reject_ciphertext_payload(&request).unwrap();

        let decoded = decode_required_hex(
            request.encrypted_manifest_hex.as_deref(),
            "encrypted_manifest_hex",
        )
        .unwrap();

        assert_eq!(decoded, b"encrypted-manifest");
        assert_eq!(action.as_wire_str(), "put_encrypted_manifest");
    }

    #[test]
    fn gateway_endpoint_rejects_put_encrypted_manifest_without_payload() {
        let request = request("put_encrypted_manifest");

        let error = decode_required_hex(
            request.encrypted_manifest_hex.as_deref(),
            "encrypted_manifest_hex",
        )
        .unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "encrypted_manifest_hex is required");
    }

    #[test]
    fn gateway_endpoint_rejects_put_encrypted_manifest_with_ciphertext_payload() {
        let mut request = request("put_encrypted_manifest");
        request.encrypted_manifest_hex = Some(hex::encode(b"encrypted-manifest"));
        request.ciphertext_hex = Some(hex::encode(b"ciphertext"));

        let error = reject_ciphertext_payload(&request).unwrap_err();

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            error.message,
            "ciphertext object payload is not allowed for this action"
        );
    }

    #[test]
    fn metadata_response_never_grants_gateway_plaintext_access() {
        let response = metadata_response(CiphertextGatewayAction::PutCiphertextObject);

        assert_eq!(response.version, WIRE_VERSION);
        assert_eq!(response.action, "put_ciphertext_object");
        assert_eq!(response.ciphertext_hex, None);
        assert_eq!(response.encrypted_manifest_hex, None);
        assert!(response.metadata_only);
        assert!(!response.gateway_plaintext_access);
    }
    #[derive(Debug, Default, Clone)]
    struct SmokeBeeStorage {
        inner: std::sync::Arc<std::sync::Mutex<SmokeBeeState>>,
    }

    #[derive(Debug, Default)]
    struct SmokeBeeState {
        pointers: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
        put_count: usize,
    }

    impl SmokeBeeStorage {
        fn put_count(&self) -> usize {
            self.inner.lock().unwrap().put_count
        }

        fn pointer_bytes(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
            let topic = BeeClient::derive_topic(bucket, key);
            self.inner.lock().unwrap().pointers.get(&topic).cloned()
        }
    }

    #[async_trait::async_trait]
    impl crate::bee::client::BeeStorage for SmokeBeeStorage {
        async fn get_bytes(&self, _reference: &str) -> anyhow::Result<Option<Bytes>> {
            Ok(None)
        }

        async fn put_bytes(
            &self,
            data: Bytes,
        ) -> anyhow::Result<crate::bee::client::BeePutBytesResult> {
            Ok(crate::bee::client::BeePutBytesResult {
                reference: format!("smoke-ref-{}", data.len()),
            })
        }

        async fn get_pointer_bytes(&self, topic: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.inner.lock().unwrap().pointers.get(&topic).cloned())
        }

        async fn put_object_and_update_pointer(
            &self,
            bucket: &str,
            key: &str,
            data: Bytes,
        ) -> anyhow::Result<crate::bee::client::FeedPointerResult> {
            let topic = BeeClient::derive_topic(bucket, key);
            let mut inner = self.inner.lock().unwrap();
            inner.put_count += 1;
            inner.pointers.insert(topic, data.to_vec());

            Ok(crate::bee::client::FeedPointerResult {
                owner: "smoke-owner".to_owned(),
                topic_hex: hex::encode(topic),
                swarm_reference: format!("smoke-swarm-{}", hex::encode(topic)),
                manifest_reference: "smoke-manifest".to_owned(),
                soc_reference: "smoke-soc".to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn gateway_bee_smoke_persists_ciphertext_object_and_fetches_ciphertext() {
        let bee = SmokeBeeStorage::default();

        let ciphertext = b"remote-object-ciphertext";

        let mut put = request("put_ciphertext_object");
        put.key = Some("docs/a.txt".to_owned());
        put.ciphertext_hex = Some(hex::encode(ciphertext));

        let put_response = execute_ciphertext_gateway_request(&bee, put).await.unwrap();

        assert_eq!(put_response.action, "put_ciphertext_object");
        assert!(put_response.metadata_only);
        assert!(!put_response.gateway_plaintext_access);
        assert_eq!(
            bee.pointer_bytes("bucket-a", "docs/a.txt"),
            Some(ciphertext.to_vec())
        );

        let mut get = request("get_ciphertext_object");
        get.key = Some("docs/a.txt".to_owned());

        let get_response = execute_ciphertext_gateway_request(&bee, get).await.unwrap();

        assert_eq!(get_response.action, "get_ciphertext_object");
        assert_eq!(get_response.ciphertext_hex, Some(hex::encode(ciphertext)));
        assert_eq!(get_response.encrypted_manifest_hex, None);
        assert!(!get_response.metadata_only);
        assert!(!get_response.gateway_plaintext_access);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_persists_and_lists_encrypted_manifest() {
        let bee = SmokeBeeStorage::default();

        let encrypted_manifest = b"encrypted-manifest-only";

        let mut put = request("put_encrypted_manifest");
        put.encrypted_manifest_hex = Some(hex::encode(encrypted_manifest));

        let put_response = execute_ciphertext_gateway_request(&bee, put).await.unwrap();

        assert_eq!(put_response.action, "put_encrypted_manifest");
        assert!(put_response.metadata_only);
        assert!(!put_response.gateway_plaintext_access);
        assert_eq!(
            bee.pointer_bytes("bucket-a", TRUSTLESS_MANIFEST_KEY),
            Some(encrypted_manifest.to_vec())
        );

        let list = request("list_ciphertext_manifest");
        let list_response = execute_ciphertext_gateway_request(&bee, list)
            .await
            .unwrap();

        assert_eq!(list_response.action, "list_ciphertext_manifest");
        assert_eq!(
            list_response.encrypted_manifest_hex,
            Some(hex::encode(encrypted_manifest))
        );
        assert_eq!(list_response.ciphertext_hex, None);
        assert!(!list_response.metadata_only);
        assert!(!list_response.gateway_plaintext_access);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_rejects_plaintext_access_claim_before_storage() {
        let bee = SmokeBeeStorage::default();

        let mut put = request("put_ciphertext_object");
        put.key = Some("docs/a.txt".to_owned());
        put.ciphertext_hex = Some(hex::encode(b"ciphertext-only"));
        put.gateway_plaintext_access = Some(true);

        let err = execute_ciphertext_gateway_request(&bee, put)
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1,
            "gateway plaintext access is forbidden for trustless requests"
        );
        assert_eq!(bee.put_count(), 0);
    }
}
