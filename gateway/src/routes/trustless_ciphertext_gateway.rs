use crate::{
    app_state::AppState,
    bee::client::BeeStorage,
    crypto::bucket_name_hash,
    orphan_reconciliation::{
        AnchorAttemptEvent, AnchorJournalAction, GatewayBeeReference, GatewayBeeReferenceKind,
        GatewayWriteJournal, JournalBucketType, record_anchor_attempt, record_anchor_failure,
        record_anchor_success,
    },
    traits::AnchorClient,
};
use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use bytes::Bytes;
use common::types::{AwsPrincipal, ChainBucketRecord, ChainBucketType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

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
#[serde(deny_unknown_fields)]
pub struct CiphertextGatewayRequest {
    version: u32,
    action: String,
    bucket: String,
    ciphertext_hex: Option<String>,
    #[serde(default)]
    ciphertext_reference_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    #[serde(default)]
    expected_manifest_reference_hex: Option<String>,
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
    ciphertext_reference_hex: Option<String>,
    encrypted_manifest_hex: Option<String>,
    encrypted_manifest_reference_hex: Option<String>,
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

    fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
        }
    }

    fn chain_failure() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "chain authorization operation failed",
        }
    }

    fn anchor_failure(err: anyhow::Error) -> Self {
        if error_chain_contains_stale_bucket_manifest_root(&err) {
            return Self::conflict("encrypted manifest precondition failed");
        }

        Self::chain_failure()
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

fn error_chain_contains_stale_bucket_manifest_root(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .flat_map(|ch| ch.to_lowercase())
            .collect::<String>()
            .contains("stalebucketmanifestroot")
    })
}

#[derive(Debug, Clone)]
struct AuthorizedTrustlessBucket {
    bucket_id: [u8; 32],
    bucket: String,
    storage_bucket: String,
    chain_bucket: ChainBucketRecord,
}

pub async fn handle(
    Extension(principal): Extension<AwsPrincipal>,
    State(state): State<AppState>,
    Json(request): Json<CiphertextGatewayRequest>,
) -> Result<Json<CiphertextGatewayResponse>, (StatusCode, String)> {
    validate_common_request(&request).map_err(RouteError::into_response)?;
    let action = CiphertextGatewayAction::parse(request.action.as_str())
        .map_err(RouteError::into_response)?;
    let authorized = authorize_trustless_bucket(&state, &principal, &request.bucket)
        .await
        .map_err(RouteError::into_response)?;

    execute_ciphertext_gateway_request(
        state.bee_client.as_ref(),
        state.anchor_client.as_ref(),
        state.orphan_journal.as_ref(),
        authorized,
        action,
        request,
    )
    .await
    .map(Json)
}

async fn authorize_trustless_bucket(
    state: &AppState,
    principal: &AwsPrincipal,
    bucket: &str,
) -> Result<AuthorizedTrustlessBucket, RouteError> {
    let bucket_id = bucket_name_hash(&principal.owner, bucket);
    let chain_bucket = state
        .registry_client
        .fetch_bucket(bucket_id)
        .await
        .map_err(|_| RouteError::chain_failure())?
        .ok_or_else(|| RouteError::not_found("trustless bucket was not found"))?;

    if chain_bucket.owner != principal.owner {
        return Err(RouteError::forbidden(
            "trustless bucket is not owned by authenticated principal",
        ));
    }

    let bucket_type = state
        .registry_client
        .fetch_bucket_type(bucket_id)
        .await
        .map_err(|_| RouteError::chain_failure())?;

    if bucket_type != Some(ChainBucketType::TrustlessPrivate) || !chain_bucket.is_private {
        return Err(RouteError::forbidden(
            "bucket is not a trustless private bucket",
        ));
    }

    Ok(AuthorizedTrustlessBucket {
        bucket_id,
        bucket: bucket.to_string(),
        storage_bucket: hex::encode(bucket_id),
        chain_bucket,
    })
}

async fn execute_ciphertext_gateway_request(
    bee_client: &dyn BeeStorage,
    anchor_client: &dyn AnchorClient,
    orphan_journal: Option<&Arc<GatewayWriteJournal>>,
    authorized: AuthorizedTrustlessBucket,
    action: CiphertextGatewayAction,
    request: CiphertextGatewayRequest,
) -> Result<CiphertextGatewayResponse, (StatusCode, String)> {
    match action {
        CiphertextGatewayAction::PutCiphertextObject => {
            reject_manifest_payload(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_reference(&request).map_err(RouteError::into_response)?;
            reject_expected_manifest_reference(&request).map_err(RouteError::into_response)?;
            let ciphertext =
                decode_required_hex(request.ciphertext_hex.as_deref(), "ciphertext_hex")
                    .map_err(RouteError::into_response)?;

            let put = bee_client
                .put_bytes(Bytes::from(ciphertext))
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?;

            Ok(metadata_response(action).with_ciphertext_reference(put.reference))
        }
        CiphertextGatewayAction::GetCiphertextObject => {
            reject_all_payloads(&request).map_err(RouteError::into_response)?;
            reject_expected_manifest_reference(&request).map_err(RouteError::into_response)?;

            let reference = decode_required_reference(
                request.ciphertext_reference_hex.as_deref(),
                "ciphertext_reference_hex",
            )
            .map_err(RouteError::into_response)?;
            let reference_hex = hex::encode(reference);
            let target = read_reference_target_bytes(
                bee_client,
                &reference_hex,
                "ciphertext object payload was not found",
            )
            .await
            .map_err(RouteError::into_response)?;

            Ok(CiphertextGatewayResponse {
                version: WIRE_VERSION,
                action: action.as_wire_str().to_string(),
                ciphertext_hex: Some(hex::encode(target.payload)),
                ciphertext_reference_hex: Some(target.reference_hex),
                encrypted_manifest_hex: None,
                encrypted_manifest_reference_hex: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            })
        }
        CiphertextGatewayAction::HeadCiphertextObject => {
            reject_all_payloads(&request).map_err(RouteError::into_response)?;
            reject_expected_manifest_reference(&request).map_err(RouteError::into_response)?;

            let reference = decode_required_reference(
                request.ciphertext_reference_hex.as_deref(),
                "ciphertext_reference_hex",
            )
            .map_err(RouteError::into_response)?;
            let reference_hex = hex::encode(reference);
            bee_client
                .get_bytes(&reference_hex)
                .await
                .map_err(|_| RouteError::storage_failure().into_response())?
                .ok_or_else(|| {
                    RouteError::not_found("ciphertext object payload was not found").into_response()
                })?;

            Ok(metadata_response(action))
        }
        CiphertextGatewayAction::ListCiphertextManifest => {
            reject_all_payloads(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_reference(&request).map_err(RouteError::into_response)?;
            reject_expected_manifest_reference(&request).map_err(RouteError::into_response)?;

            if authorized.chain_bucket.bucket_manifest_root.is_empty() {
                return Ok(CiphertextGatewayResponse {
                    version: WIRE_VERSION,
                    action: action.as_wire_str().to_string(),
                    ciphertext_hex: None,
                    ciphertext_reference_hex: None,
                    encrypted_manifest_hex: None,
                    encrypted_manifest_reference_hex: None,
                    metadata_only: true,
                    gateway_plaintext_access: false,
                });
            }

            let reference_hex = hex::encode(&authorized.chain_bucket.bucket_manifest_root);
            let encrypted_manifest = read_reference_target_bytes(
                bee_client,
                &reference_hex,
                "encrypted manifest payload was not found",
            )
            .await
            .map_err(RouteError::into_response)?;

            Ok(CiphertextGatewayResponse {
                version: WIRE_VERSION,
                action: action.as_wire_str().to_string(),
                ciphertext_hex: None,
                ciphertext_reference_hex: None,
                encrypted_manifest_hex: Some(hex::encode(encrypted_manifest.payload)),
                encrypted_manifest_reference_hex: Some(encrypted_manifest.reference_hex),
                metadata_only: false,
                gateway_plaintext_access: false,
            })
        }
        CiphertextGatewayAction::PutEncryptedManifest => {
            reject_ciphertext_payload(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_reference(&request).map_err(RouteError::into_response)?;
            let encrypted_manifest = decode_required_hex(
                request.encrypted_manifest_hex.as_deref(),
                "encrypted_manifest_hex",
            )
            .map_err(RouteError::into_response)?;

            let manifest_reference = write_encrypted_manifest_with_anchor(
                bee_client,
                anchor_client,
                orphan_journal,
                &authorized,
                action,
                encrypted_manifest,
                request.expected_manifest_reference_hex.as_deref(),
            )
            .await
            .map_err(RouteError::into_response)?;

            Ok(metadata_response(action).with_encrypted_manifest_reference(manifest_reference))
        }
        CiphertextGatewayAction::DeleteCiphertextObject => {
            reject_ciphertext_payload(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_reference(&request).map_err(RouteError::into_response)?;
            let encrypted_manifest = decode_required_hex(
                request.encrypted_manifest_hex.as_deref(),
                "encrypted_manifest_hex",
            )
            .map_err(RouteError::into_response)?;
            decode_required_reference(
                request.expected_manifest_reference_hex.as_deref(),
                "expected_manifest_reference_hex",
            )
            .map_err(RouteError::into_response)?;

            let manifest_reference = write_encrypted_manifest_with_anchor(
                bee_client,
                anchor_client,
                orphan_journal,
                &authorized,
                action,
                encrypted_manifest,
                request.expected_manifest_reference_hex.as_deref(),
            )
            .await
            .map_err(RouteError::into_response)?;

            Ok(metadata_response(action).with_encrypted_manifest_reference(manifest_reference))
        }
        CiphertextGatewayAction::CreateTrustlessBucket => {
            reject_all_payloads(&request).map_err(RouteError::into_response)?;
            reject_ciphertext_reference(&request).map_err(RouteError::into_response)?;
            reject_expected_manifest_reference(&request).map_err(RouteError::into_response)?;

            Ok(metadata_response(action))
        }
    }
}

struct PointerTargetBytes {
    reference_hex: String,
    payload: Vec<u8>,
}

async fn read_reference_target_bytes(
    bee_client: &dyn BeeStorage,
    reference_hex: &str,
    payload_missing_message: &'static str,
) -> Result<PointerTargetBytes, RouteError> {
    let payload = bee_client
        .get_bytes(reference_hex)
        .await
        .map_err(|_| RouteError::storage_failure())?
        .ok_or_else(|| RouteError::not_found(payload_missing_message))?;

    Ok(PointerTargetBytes {
        reference_hex: reference_hex.to_owned(),
        payload: payload.to_vec(),
    })
}

fn metadata_response(action: CiphertextGatewayAction) -> CiphertextGatewayResponse {
    CiphertextGatewayResponse {
        version: WIRE_VERSION,
        action: action.as_wire_str().to_string(),
        ciphertext_hex: None,
        ciphertext_reference_hex: None,
        encrypted_manifest_hex: None,
        encrypted_manifest_reference_hex: None,
        metadata_only: true,
        gateway_plaintext_access: false,
    }
}

impl CiphertextGatewayResponse {
    fn with_ciphertext_reference(mut self, reference_hex: String) -> Self {
        self.ciphertext_reference_hex = Some(reference_hex);
        self
    }

    fn with_encrypted_manifest_reference(mut self, reference_hex: String) -> Self {
        self.encrypted_manifest_reference_hex = Some(reference_hex);
        self
    }
}

async fn write_encrypted_manifest_with_anchor(
    bee_client: &dyn BeeStorage,
    anchor_client: &dyn AnchorClient,
    orphan_journal: Option<&Arc<GatewayWriteJournal>>,
    authorized: &AuthorizedTrustlessBucket,
    action: CiphertextGatewayAction,
    encrypted_manifest: Vec<u8>,
    expected_manifest_reference_hex: Option<&str>,
) -> Result<String, RouteError> {
    validate_manifest_precondition(
        &authorized.chain_bucket.bucket_manifest_root,
        expected_manifest_reference_hex,
    )?;

    let put = bee_client
        .put_object_and_update_pointer(
            &authorized.storage_bucket,
            TRUSTLESS_MANIFEST_KEY,
            Bytes::from(encrypted_manifest),
        )
        .await
        .map_err(|_| RouteError::storage_failure())?;

    let expected_root = hex::encode(&authorized.chain_bucket.bucket_manifest_root);
    let journal_action = match action {
        CiphertextGatewayAction::PutEncryptedManifest => {
            AnchorJournalAction::TrustlessPutEncryptedManifest
        }
        CiphertextGatewayAction::DeleteCiphertextObject => {
            AnchorJournalAction::TrustlessDeleteEncryptedManifest
        }
        _ => unreachable!("manifest anchor writes are only valid for manifest actions"),
    };

    let attempt_event_id = record_anchor_attempt(
        orphan_journal,
        AnchorAttemptEvent {
            action: journal_action,
            bucket: authorized.bucket.clone(),
            owner_hex: hex::encode(authorized.chain_bucket.owner),
            bucket_id_hex: hex::encode(authorized.bucket_id),
            bucket_type: JournalBucketType::TrustlessPrivate,
            expected_bucket_manifest_root_hex: expected_root.clone(),
            new_bucket_manifest_root_hex: put.swarm_reference.clone(),
            references: vec![GatewayBeeReference::new(
                put.swarm_reference.clone(),
                GatewayBeeReferenceKind::TrustlessEncryptedManifest,
            )],
        },
    )
    .await
    .map_err(|_| RouteError::storage_failure())?;

    let result = match action {
        CiphertextGatewayAction::PutEncryptedManifest => {
            anchor_client
                .update_bucket_manifest_root_for_put_anchor(
                    authorized.bucket_id,
                    expected_root,
                    put.swarm_reference.clone(),
                )
                .await
        }
        CiphertextGatewayAction::DeleteCiphertextObject => {
            anchor_client
                .update_bucket_manifest_root_for_delete_anchor(
                    authorized.bucket_id,
                    expected_root,
                    put.swarm_reference.clone(),
                )
                .await
        }
        _ => unreachable!("manifest anchor writes are only valid for manifest actions"),
    };

    match result {
        Ok(tx_hash) => {
            if let Err(err) = record_anchor_success(orphan_journal, attempt_event_id, tx_hash).await
            {
                warn!("failed to record trustless encrypted manifest anchor success: {err}");
            }
        }
        Err(err) => {
            if let Err(journal_err) =
                record_anchor_failure(orphan_journal, attempt_event_id, &err).await
            {
                warn!(
                    "failed to record trustless encrypted manifest anchor failure: {journal_err}"
                );
            }
            return Err(RouteError::anchor_failure(err));
        }
    }

    Ok(put.swarm_reference)
}

fn validate_manifest_precondition(
    current_manifest_root: &[u8],
    expected_manifest_reference_hex: Option<&str>,
) -> Result<(), RouteError> {
    let expected = decode_optional_reference(
        expected_manifest_reference_hex,
        "expected_manifest_reference_hex",
    )?;

    match (current_manifest_root.is_empty(), expected) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err(RouteError::conflict(
            "encrypted manifest precondition failed",
        )),
        (false, Some(expected)) if current_manifest_root == expected.as_slice() => Ok(()),
        (false, _) => Err(RouteError::conflict(
            "encrypted manifest precondition failed",
        )),
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

fn reject_ciphertext_reference(request: &CiphertextGatewayRequest) -> Result<(), RouteError> {
    if request.ciphertext_reference_hex.is_some() {
        return Err(RouteError::bad_request(
            "ciphertext reference is not allowed for this action",
        ));
    }

    Ok(())
}

fn reject_expected_manifest_reference(
    request: &CiphertextGatewayRequest,
) -> Result<(), RouteError> {
    if request.expected_manifest_reference_hex.is_some() {
        return Err(RouteError::bad_request(
            "expected manifest reference is not allowed for this action",
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

fn decode_optional_reference(
    value: Option<&str>,
    field_name: &'static str,
) -> Result<Option<Vec<u8>>, RouteError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    if value.eq_ignore_ascii_case("empty") {
        return Ok(None);
    }

    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .map_err(|_| RouteError::bad_request(invalid_reference_message(field_name)))?;

    if bytes.len() != 32 {
        return Err(RouteError::bad_request(invalid_reference_message(
            field_name,
        )));
    }

    Ok(Some(bytes))
}

fn decode_required_reference(
    value: Option<&str>,
    field_name: &'static str,
) -> Result<Vec<u8>, RouteError> {
    decode_optional_reference(value, field_name)?
        .ok_or_else(|| RouteError::bad_request(required_reference_message(field_name)))
}

fn required_hex_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_hex" => "ciphertext_hex is required",
        "encrypted_manifest_hex" => "encrypted_manifest_hex is required",
        _ => "required hex payload is missing",
    }
}

fn required_reference_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_reference_hex" => "ciphertext_reference_hex is required",
        "expected_manifest_reference_hex" => "expected_manifest_reference_hex is required",
        _ => "reference is required",
    }
}

fn invalid_hex_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_hex" => "ciphertext_hex must be valid hex",
        "encrypted_manifest_hex" => "encrypted_manifest_hex must be valid hex",
        _ => "hex payload must be valid hex",
    }
}

fn invalid_reference_message(field_name: &'static str) -> &'static str {
    match field_name {
        "ciphertext_reference_hex" => "ciphertext_reference_hex must be a 32-byte hex reference",
        "expected_manifest_reference_hex" => {
            "expected_manifest_reference_hex must be a 32-byte hex reference"
        }
        _ => "reference must be a 32-byte hex reference",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bee::client::BeeClient;

    fn request(action: &str) -> CiphertextGatewayRequest {
        CiphertextGatewayRequest {
            version: WIRE_VERSION,
            action: action.to_string(),
            bucket: "bucket-a".to_string(),
            ciphertext_hex: None,
            ciphertext_reference_hex: None,
            encrypted_manifest_hex: None,
            expected_manifest_reference_hex: None,
            metadata_only: None,
            gateway_plaintext_access: None,
        }
    }

    fn authorized_bucket(manifest_root: Vec<u8>) -> AuthorizedTrustlessBucket {
        let bucket_id = [7u8; 32];
        AuthorizedTrustlessBucket {
            bucket_id,
            bucket: "bucket-a".to_string(),
            storage_bucket: hex::encode(bucket_id),
            chain_bucket: ChainBucketRecord {
                owner: [9u8; 32],
                is_private: true,
                encryption_version: 1,
                creation_date: 0,
                bucket_manifest_root: manifest_root,
            },
        }
    }

    async fn execute_for_test(
        bee: &SmokeBeeStorage,
        anchor: &SmokeAnchorClient,
        authorized: AuthorizedTrustlessBucket,
        request: CiphertextGatewayRequest,
    ) -> Result<CiphertextGatewayResponse, (StatusCode, String)> {
        validate_common_request(&request).map_err(RouteError::into_response)?;
        let action = CiphertextGatewayAction::parse(request.action.as_str())
            .map_err(RouteError::into_response)?;

        execute_ciphertext_gateway_request(bee, anchor, None, authorized, action, request).await
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
    fn rejects_object_key_wire_field() {
        let err = serde_json::from_value::<CiphertextGatewayRequest>(serde_json::json!({
            "version": WIRE_VERSION,
            "action": "put_ciphertext_object",
            "bucket": "bucket-a",
            "key": "private/object.txt",
            "ciphertext_hex": hex::encode(b"ciphertext")
        }))
        .unwrap_err();

        assert!(err.to_string().contains("unknown field `key`"));
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
        assert_eq!(response.ciphertext_reference_hex, None);
        assert_eq!(response.encrypted_manifest_hex, None);
        assert_eq!(response.encrypted_manifest_reference_hex, None);
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
        objects: std::collections::BTreeMap<String, Vec<u8>>,
        put_count: usize,
    }

    impl SmokeBeeStorage {
        fn put_count(&self) -> usize {
            self.inner.lock().unwrap().put_count
        }

        fn pointed_object_bytes(&self, bucket: &str, key: &str) -> Option<Vec<u8>> {
            let topic = BeeClient::derive_topic(bucket, key);
            let inner = self.inner.lock().unwrap();
            let reference = hex::encode(inner.pointers.get(&topic)?);
            inner.objects.get(&reference).cloned()
        }
    }

    #[derive(Debug, Default, Clone)]
    struct SmokeAnchorClient {
        inner: std::sync::Arc<std::sync::Mutex<SmokeAnchorState>>,
    }

    #[derive(Debug, Default)]
    struct SmokeAnchorState {
        put_updates: Vec<(String, String)>,
        delete_updates: Vec<(String, String)>,
        fail_put_with_stale_root: bool,
    }

    impl SmokeAnchorClient {
        fn put_updates(&self) -> Vec<(String, String)> {
            self.inner.lock().unwrap().put_updates.clone()
        }

        fn delete_updates(&self) -> Vec<(String, String)> {
            self.inner.lock().unwrap().delete_updates.clone()
        }

        fn fail_put_with_stale_root(&self) {
            self.inner.lock().unwrap().fail_put_with_stale_root = true;
        }
    }

    #[async_trait::async_trait]
    impl AnchorClient for SmokeAnchorClient {
        async fn create_bucket_anchor(
            &self,
            _owner: common::types::SubstrateAddress32,
            _bucket_id: [u8; 32],
            _is_private: bool,
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            anyhow::bail!("create_bucket_anchor should not be used by ciphertext endpoint tests")
        }

        async fn create_trustless_bucket_anchor(
            &self,
            _owner: common::types::SubstrateAddress32,
            _bucket_id: [u8; 32],
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            anyhow::bail!(
                "create_trustless_bucket_anchor should not be used by ciphertext endpoint tests"
            )
        }

        async fn delete_bucket_anchor(
            &self,
            _bucket_id: [u8; 32],
            _owner_signature: [u8; 64],
            _expected_owner_catalog_root: String,
            _owner_catalog_root: String,
        ) -> anyhow::Result<String> {
            anyhow::bail!("delete_bucket_anchor should not be used by ciphertext endpoint tests")
        }

        async fn update_bucket_manifest_root_for_put_anchor(
            &self,
            _bucket_id: [u8; 32],
            expected_bucket_manifest_root: String,
            bucket_manifest_root: String,
        ) -> anyhow::Result<String> {
            self.inner
                .lock()
                .unwrap()
                .put_updates
                .push((expected_bucket_manifest_root, bucket_manifest_root.clone()));
            if self.inner.lock().unwrap().fail_put_with_stale_root {
                anyhow::bail!(
                    "bucket contract error for bucket::update_bucket_manifest_root_for_put_cas: StaleBucketManifestRoot"
                );
            }
            Ok(bucket_manifest_root)
        }

        async fn update_bucket_manifest_root_for_delete_anchor(
            &self,
            _bucket_id: [u8; 32],
            expected_bucket_manifest_root: String,
            bucket_manifest_root: String,
        ) -> anyhow::Result<String> {
            self.inner
                .lock()
                .unwrap()
                .delete_updates
                .push((expected_bucket_manifest_root, bucket_manifest_root.clone()));
            Ok(bucket_manifest_root)
        }

        async fn submit_anchor_object(
            &self,
            _owner: common::types::SubstrateAddress32,
            _bucket_id: [u8; 32],
            _object_key_id: [u8; 32],
            _swarm_ref: String,
            _expected_bucket_manifest_root: String,
            _bucket_manifest_root: String,
            _size: u64,
            _etag: [u8; 32],
        ) -> anyhow::Result<String> {
            anyhow::bail!("submit_anchor_object should not be used by ciphertext endpoint tests")
        }
    }

    #[async_trait::async_trait]
    impl crate::bee::client::BeeStorage for SmokeBeeStorage {
        async fn get_bytes(&self, reference: &str) -> anyhow::Result<Option<Bytes>> {
            Ok(self
                .inner
                .lock()
                .unwrap()
                .objects
                .get(reference)
                .cloned()
                .map(Bytes::from))
        }

        async fn put_bytes(
            &self,
            data: Bytes,
        ) -> anyhow::Result<crate::bee::client::BeePutBytesResult> {
            let mut inner = self.inner.lock().unwrap();
            inner.put_count += 1;
            let reference = format!("{:064x}", inner.put_count);
            inner.objects.insert(reference.clone(), data.to_vec());

            Ok(crate::bee::client::BeePutBytesResult { reference })
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

            let reference = format!("{:064x}", inner.put_count);
            let reference_bytes = hex::decode(&reference).unwrap();

            inner.objects.insert(reference.clone(), data.to_vec());
            inner.pointers.insert(topic, reference_bytes);

            Ok(crate::bee::client::FeedPointerResult {
                owner: "smoke-owner".to_owned(),
                topic_hex: hex::encode(topic),
                swarm_reference: reference,
                manifest_reference: "smoke-manifest".to_owned(),
                soc_reference: "smoke-soc".to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn gateway_bee_smoke_persists_ciphertext_object_and_fetches_ciphertext() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        let ciphertext = b"remote-object-ciphertext";

        let mut put = request("put_ciphertext_object");
        put.ciphertext_hex = Some(hex::encode(ciphertext));

        let put_response = execute_for_test(&bee, &anchor, authorized.clone(), put)
            .await
            .unwrap();

        assert_eq!(put_response.action, "put_ciphertext_object");
        assert!(put_response.metadata_only);
        assert!(!put_response.gateway_plaintext_access);
        let ciphertext_reference = put_response.ciphertext_reference_hex.clone().unwrap();
        assert_eq!(
            bee.inner
                .lock()
                .unwrap()
                .objects
                .get(&ciphertext_reference)
                .cloned(),
            Some(ciphertext.to_vec())
        );

        let mut get = request("get_ciphertext_object");
        get.ciphertext_reference_hex = Some(ciphertext_reference.clone());

        let get_response = execute_for_test(&bee, &anchor, authorized, get)
            .await
            .unwrap();

        assert_eq!(get_response.action, "get_ciphertext_object");
        assert_eq!(get_response.ciphertext_hex, Some(hex::encode(ciphertext)));
        assert_eq!(
            get_response.ciphertext_reference_hex,
            Some(ciphertext_reference)
        );
        assert_eq!(get_response.encrypted_manifest_hex, None);
        assert!(!get_response.metadata_only);
        assert!(!get_response.gateway_plaintext_access);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_persists_and_lists_encrypted_manifest() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        let encrypted_manifest = b"encrypted-manifest-only";

        let mut put = request("put_encrypted_manifest");
        put.encrypted_manifest_hex = Some(hex::encode(encrypted_manifest));

        let put_response = execute_for_test(&bee, &anchor, authorized.clone(), put)
            .await
            .unwrap();

        assert_eq!(put_response.action, "put_encrypted_manifest");
        assert!(put_response.metadata_only);
        assert!(!put_response.gateway_plaintext_access);
        let manifest_reference = put_response
            .encrypted_manifest_reference_hex
            .clone()
            .unwrap();
        assert_eq!(
            bee.pointed_object_bytes(&authorized.storage_bucket, TRUSTLESS_MANIFEST_KEY),
            Some(encrypted_manifest.to_vec())
        );
        assert_eq!(
            anchor.put_updates(),
            vec![(String::new(), manifest_reference.clone())]
        );

        let authorized = authorized_bucket(hex::decode(&manifest_reference).unwrap());
        let list = request("list_ciphertext_manifest");
        let list_response = execute_for_test(&bee, &anchor, authorized, list)
            .await
            .unwrap();

        assert_eq!(list_response.action, "list_ciphertext_manifest");
        assert_eq!(
            list_response.encrypted_manifest_hex,
            Some(hex::encode(encrypted_manifest))
        );
        assert_eq!(
            list_response.encrypted_manifest_reference_hex,
            Some(manifest_reference)
        );
        assert_eq!(list_response.ciphertext_hex, None);
        assert!(!list_response.metadata_only);
        assert!(!list_response.gateway_plaintext_access);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_stale_manifest_anchor_is_conflict_after_bee_write() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        anchor.fail_put_with_stale_root();
        let authorized = authorized_bucket(Vec::new());

        let encrypted_manifest = b"encrypted-manifest-that-lost-cas";

        let mut put = request("put_encrypted_manifest");
        put.encrypted_manifest_hex = Some(hex::encode(encrypted_manifest));

        let err = execute_for_test(&bee, &anchor, authorized.clone(), put)
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(err.1, "encrypted manifest precondition failed");
        assert_eq!(
            bee.pointed_object_bytes(&authorized.storage_bucket, TRUSTLESS_MANIFEST_KEY),
            Some(encrypted_manifest.to_vec()),
            "failed CAS may leave encrypted manifest bytes in Bee, but the chain root is unchanged"
        );
        assert_eq!(anchor.put_updates().len(), 1);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_delete_requires_expected_manifest_reference_before_storage() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        let mut delete = request("delete_ciphertext_object");
        delete.encrypted_manifest_hex = Some(hex::encode(b"encrypted-manifest-after-delete"));

        let err = execute_for_test(&bee, &anchor, authorized, delete)
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "expected_manifest_reference_hex is required");
        assert_eq!(bee.put_count(), 0);
        assert!(anchor.delete_updates().is_empty());
    }

    #[tokio::test]
    async fn gateway_bee_smoke_list_manifest_returns_empty_state_for_new_bucket() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        let list = request("list_ciphertext_manifest");
        let list_response = execute_for_test(&bee, &anchor, authorized, list)
            .await
            .unwrap();

        assert_eq!(list_response.action, "list_ciphertext_manifest");
        assert_eq!(list_response.encrypted_manifest_hex, None);
        assert_eq!(list_response.encrypted_manifest_reference_hex, None);
        assert_eq!(list_response.ciphertext_hex, None);
        assert!(list_response.metadata_only);
        assert!(!list_response.gateway_plaintext_access);
    }

    #[tokio::test]
    async fn gateway_bee_smoke_get_requires_direct_ciphertext_reference_before_pointer_lookup() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        {
            let topic =
                BeeClient::derive_topic(&authorized.storage_bucket, "docs/missing-payload.txt");
            bee.inner
                .lock()
                .unwrap()
                .pointers
                .insert(topic, hex::decode(format!("{:064x}", 99)).unwrap());
        }

        let get = request("get_ciphertext_object");

        let err = execute_for_test(&bee, &anchor, authorized, get)
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "ciphertext_reference_hex is required");
    }

    #[tokio::test]
    async fn gateway_bee_smoke_rejects_plaintext_access_claim_before_storage() {
        let bee = SmokeBeeStorage::default();
        let anchor = SmokeAnchorClient::default();
        let authorized = authorized_bucket(Vec::new());

        let mut put = request("put_ciphertext_object");
        put.ciphertext_hex = Some(hex::encode(b"ciphertext-only"));
        put.gateway_plaintext_access = Some(true);

        let err = execute_for_test(&bee, &anchor, authorized, put)
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.1,
            "gateway plaintext access is forbidden for trustless requests"
        );
        assert_eq!(bee.put_count(), 0);
    }

    #[test]
    fn manifest_precondition_requires_current_root_for_existing_manifest() {
        let current = vec![3u8; 32];
        let current_hex = hex::encode(&current);

        let error = validate_manifest_precondition(&current, None).unwrap_err();

        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.message, "encrypted manifest precondition failed");
        assert!(validate_manifest_precondition(&current, Some(&current_hex)).is_ok());
    }
}
