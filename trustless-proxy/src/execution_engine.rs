use aes_gcm::aead::{rand_core::RngCore, OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::encryption::{
    TrustlessEncryptRequest, TrustlessEncryptionBoundary, TrustlessEncryptionError,
};
use crate::gateway_boundary::{CiphertextGatewayBoundary, CiphertextGatewayBoundaryError};
use crate::http_mapping::{
    LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext, LocalTrustlessHttpResponse,
};
use crate::local_keystore::LocalKeystoreResolver;
use crate::manifest::{
    EncryptedTrustlessManifest, TrustlessManifest, TrustlessManifestBoundary,
    TrustlessManifestCipher, TrustlessManifestEntry, TrustlessManifestError,
};
use crate::planner::{PlannerError, RemoteGatewayAction, TrustlessRoutePlanner};
use crate::preflight::{
    PreflightError, TrustlessOperationPreflightBuilder, TrustlessPreflightRequest,
};
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::{
    RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
};
use crate::runtime::{
    LocalTrustlessRuntime, LocalTrustlessRuntimeError, LocalTrustlessRuntimePreparedResponse,
    LocalTrustlessRuntimeRemotePayload,
};
use crate::s3_surface::LocalS3Operation;
use crate::server::{LocalTrustlessServer, LocalTrustlessServerError};
use crate::types::RecipientEnvelopeContext;

const LOCAL_LIST_CONTINUATION_TOKEN_PREFIX: &str = "s3gw-local-list-v1";

pub struct LocalTrustlessExecutionEngine<C, RK, LK, G> {
    server: LocalTrustlessServer,
    proxy_config: TrustlessProxyConfig,
    preflight_builder: TrustlessOperationPreflightBuilder<RK, LK>,
    manifest_cipher: C,
    remote_gateway_executor: TrustlessRemoteGatewayExecutor<G>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessExecutionInput {
    pub http_request: LocalTrustlessHttpRequest,
    pub http_context: LocalTrustlessHttpRequestContext,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentTrustlessManifest {
    manifest: TrustlessManifest,
    encrypted_manifest_reference_hex: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessExecutionEngineError {
    #[error(transparent)]
    Server(LocalTrustlessServerError),

    #[error(transparent)]
    Runtime(LocalTrustlessRuntimeError),

    #[error(transparent)]
    RemoteGateway(RemoteGatewayClientError),

    #[error(transparent)]
    GatewayBoundary(CiphertextGatewayBoundaryError),

    #[error(transparent)]
    Planner(PlannerError),

    #[error(transparent)]
    Manifest(TrustlessManifestError),

    #[error(transparent)]
    Preflight(PreflightError),

    #[error(transparent)]
    Encryption(TrustlessEncryptionError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("prepared runtime response is missing object key")]
    MissingPreparedObjectKey,

    #[error("remote gateway returned unexpected action: expected {expected:?}, got {actual:?}")]
    UnexpectedRemoteResponseAction {
        expected: RemoteGatewayAction,
        actual: RemoteGatewayAction,
    },

    #[error("execution engine does not support operation yet: {0:?}")]
    UnsupportedOperation(LocalS3Operation),

    #[error("invalid ListObjectsV2 query: {0}")]
    InvalidListQuery(String),

    #[error("invalid ListObjectsV2 continuation token: {0}")]
    InvalidListContinuationToken(String),
}

impl From<LocalTrustlessServerError> for LocalTrustlessExecutionEngineError {
    fn from(error: LocalTrustlessServerError) -> Self {
        Self::Server(error)
    }
}

impl From<LocalTrustlessRuntimeError> for LocalTrustlessExecutionEngineError {
    fn from(error: LocalTrustlessRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<RemoteGatewayClientError> for LocalTrustlessExecutionEngineError {
    fn from(error: RemoteGatewayClientError) -> Self {
        Self::RemoteGateway(error)
    }
}

impl From<CiphertextGatewayBoundaryError> for LocalTrustlessExecutionEngineError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::GatewayBoundary(error)
    }
}

impl From<PlannerError> for LocalTrustlessExecutionEngineError {
    fn from(error: PlannerError) -> Self {
        Self::Planner(error)
    }
}

impl From<TrustlessManifestError> for LocalTrustlessExecutionEngineError {
    fn from(error: TrustlessManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<PreflightError> for LocalTrustlessExecutionEngineError {
    fn from(error: PreflightError) -> Self {
        Self::Preflight(error)
    }
}

impl From<TrustlessEncryptionError> for LocalTrustlessExecutionEngineError {
    fn from(error: TrustlessEncryptionError) -> Self {
        Self::Encryption(error)
    }
}

impl<C, RK, LK, G> LocalTrustlessExecutionEngine<C, RK, LK, G>
where
    C: TrustlessManifestCipher + Clone,
    RK: RecipientKeyResolver,
    LK: LocalKeystoreResolver,
    G: TrustlessRemoteGatewayClient,
{
    pub fn new(
        server: LocalTrustlessServer,
        proxy_config: TrustlessProxyConfig,
        preflight_builder: TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        remote_gateway_executor: TrustlessRemoteGatewayExecutor<G>,
    ) -> Self {
        Self {
            server,
            proxy_config,
            preflight_builder,
            manifest_cipher,
            remote_gateway_executor,
        }
    }

    pub fn execute_http_request(
        &self,
        input: LocalTrustlessExecutionInput,
    ) -> Result<LocalTrustlessHttpResponse, LocalTrustlessExecutionEngineError> {
        let request_query = input.http_request.query.clone();
        let prepared = self
            .server
            .prepare_http_request(input.http_request, input.http_context)?;

        if prepared.gateway_plaintext_access || prepared.http_response.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        match prepared.operation {
            LocalS3Operation::PutObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;
                let manifest_context = manifest_envelope_context(&input.envelope_context);
                let current_manifest =
                    self.fetch_and_decrypt_current_manifest(runtime_prepared, &manifest_context)?;

                let object_key = runtime_prepared_object_key(runtime_prepared)?;
                let object_context_id = current_manifest
                    .manifest
                    .entries
                    .iter()
                    .find(|entry| entry.object_key == object_key)
                    .map(|entry| entry.object_key_id.clone())
                    .unwrap_or_else(fresh_object_context_id_hex);
                let object_context =
                    object_envelope_context(&input.envelope_context, object_context_id.clone());
                let plaintext = runtime_prepared_put_plaintext(runtime_prepared)?;
                let etag = sha256_hex(&plaintext);
                let mut preflight_request = runtime_prepared_preflight_request(runtime_prepared);
                preflight_request.object_key_id = Some(object_context_id.clone());
                let preflight = self
                    .preflight_builder
                    .preflight_put_object(preflight_request)?;
                let keyring =
                    LocalTrustlessRuntime::build_aws_esdk_raw_rsa_keyring_from_local_selection(
                        &self.proxy_config,
                        preflight.local_private_key.clone(),
                    )?;
                let encrypted_object = TrustlessEncryptionBoundary::new(keyring).encrypt_for_put(
                    TrustlessEncryptRequest {
                        plaintext,
                        preflight,
                    },
                )?;
                let ciphertext_size = encrypted_object.ciphertext.len() as u64;
                let object_request = CiphertextGatewayBoundary::put_ciphertext_request(
                    &TrustlessRoutePlanner::plan_put_object(
                        runtime_prepared_bucket(runtime_prepared),
                        object_key.clone(),
                        Some(&object_context),
                    )?,
                    &input.envelope_context.bucket_id,
                    encrypted_object,
                )?;

                let object_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    object_request,
                    &self.remote_gateway_executor,
                )?;

                self.require_response_action(
                    &object_response,
                    RemoteGatewayAction::PutCiphertextObject,
                )?;

                let ciphertext_ref = object_response
                    .ciphertext_reference_hex
                    .clone()
                    .filter(|reference| !reference.trim().is_empty())
                    .ok_or(LocalTrustlessExecutionEngineError::Runtime(
                        LocalTrustlessRuntimeError::MissingCiphertextReference,
                    ))?;
                let manifest_entry = TrustlessManifestEntry {
                    object_key,
                    object_key_id: object_context_id,
                    ciphertext_ref,
                    ciphertext_size,
                    content_type: None,
                    etag: Some(etag),
                };
                let manifest_boundary =
                    TrustlessManifestBoundary::new(self.manifest_cipher.clone());
                let manifest_mutation = manifest_boundary
                    .upsert_entry_locally(current_manifest.manifest, manifest_entry)?;
                let manifest_write = manifest_boundary
                    .encrypt_manifest_locally(manifest_mutation.manifest, manifest_context)?;

                if object_response.gateway_plaintext_access
                    || prepared.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                let manifest_request = CiphertextGatewayBoundary::put_encrypted_manifest_request(
                    input.envelope_context.bucket_id.clone(),
                    manifest_write.encrypted_manifest.ciphertext,
                    current_manifest.encrypted_manifest_reference_hex,
                )?;

                let manifest_response = self.remote_gateway_executor.execute(manifest_request)?;

                self.require_response_action(
                    &manifest_response,
                    RemoteGatewayAction::PutEncryptedManifest,
                )?;

                if manifest_response.gateway_plaintext_access {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(completed_metadata_http_response(prepared.operation))
            }
            LocalS3Operation::GetObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;
                let manifest_context = manifest_envelope_context(&input.envelope_context);
                let current_manifest =
                    self.fetch_and_decrypt_current_manifest(runtime_prepared, &manifest_context)?;
                let manifest_entry = manifest_entry_for_runtime_request(
                    &current_manifest.manifest,
                    runtime_prepared,
                )?;

                let request = LocalTrustlessRuntime::build_prepared_remote_request(
                    runtime_prepared,
                    LocalTrustlessRuntimeRemotePayload::CiphertextReference(
                        manifest_entry.ciphertext_ref,
                    ),
                )?;

                let gateway_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    request,
                    &self.remote_gateway_executor,
                )?;

                let completion = self.server.complete_prepared_get_with_configured_aws_esdk(
                    prepared,
                    gateway_response,
                    object_envelope_context(&input.envelope_context, manifest_entry.object_key_id),
                    &self.proxy_config,
                    &self.preflight_builder,
                    self.manifest_cipher.clone(),
                )?;

                if completion.gateway_plaintext_access
                    || completion.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(completion.http_response)
            }
            LocalS3Operation::HeadObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;
                let manifest_context = manifest_envelope_context(&input.envelope_context);
                let current_manifest =
                    self.fetch_and_decrypt_current_manifest(runtime_prepared, &manifest_context)?;
                let manifest_entry = manifest_entry_for_runtime_request(
                    &current_manifest.manifest,
                    runtime_prepared,
                )?;

                let request = LocalTrustlessRuntime::build_prepared_remote_request(
                    runtime_prepared,
                    LocalTrustlessRuntimeRemotePayload::CiphertextReference(
                        manifest_entry.ciphertext_ref,
                    ),
                )?;

                let gateway_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    request,
                    &self.remote_gateway_executor,
                )?;

                self.require_response_action(
                    &gateway_response,
                    RemoteGatewayAction::HeadCiphertextObject,
                )?;

                if gateway_response.gateway_plaintext_access
                    || prepared.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(completed_metadata_http_response(prepared.operation))
            }
            LocalS3Operation::ListObjectsV2 => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;
                let manifest_context = manifest_envelope_context(&input.envelope_context);
                let current_manifest =
                    self.fetch_and_decrypt_current_manifest(runtime_prepared, &manifest_context)?;

                let list_query = parse_local_list_query(request_query.as_deref())?;
                let prefix = runtime_prepared_prefix(runtime_prepared);
                if list_query.prefix != prefix {
                    return Err(LocalTrustlessExecutionEngineError::InvalidListQuery(
                        "parsed list prefix does not match prepared request prefix".to_owned(),
                    ));
                }
                let list_snapshot = resolve_local_list_snapshot(
                    &current_manifest,
                    &input.envelope_context.bucket_id,
                    prefix.as_deref().unwrap_or_default(),
                    list_query.continuation_token.as_deref(),
                )?;
                let list_result = TrustlessManifestBoundary::new(self.manifest_cipher.clone())
                    .list_metadata_locally(&current_manifest.manifest, prefix.as_deref())?;

                if list_result.gateway_plaintext_access
                    || prepared.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                let page = page_trustless_list_entries(
                    list_result.entries,
                    list_query.max_keys,
                    list_snapshot.after_key.as_deref(),
                );
                let next_continuation_token = page
                    .next_after_key
                    .as_deref()
                    .map(|after_key| {
                        encode_local_list_continuation_token(&list_snapshot, after_key)
                    })
                    .transpose()?;
                let body = trustless_list_objects_v2_response_body(
                    &runtime_prepared_bucket(runtime_prepared),
                    prefix.as_deref(),
                    list_query.max_keys,
                    list_query.continuation_token.as_deref(),
                    page.is_truncated,
                    next_continuation_token.as_deref(),
                    &page.entries,
                );

                Ok(completed_list_http_response(body))
            }
            LocalS3Operation::DeleteObject => {
                let runtime_prepared =
                    &prepared.handler_prepared_response.runtime_prepared_response;
                let manifest_context = manifest_envelope_context(&input.envelope_context);
                let current_manifest =
                    self.fetch_and_decrypt_current_manifest(runtime_prepared, &manifest_context)?;
                let manifest_entry = manifest_entry_for_runtime_request(
                    &current_manifest.manifest,
                    runtime_prepared,
                )?;

                let mut preflight_request = runtime_prepared_preflight_request(runtime_prepared);
                preflight_request.object_key_id = Some(manifest_entry.object_key_id.clone());
                let preflight = self
                    .preflight_builder
                    .preflight_delete_object(preflight_request)?;
                let manifest_boundary =
                    TrustlessManifestBoundary::new(self.manifest_cipher.clone());
                let manifest_mutation = manifest_boundary.remove_entry_locally(
                    current_manifest.manifest,
                    manifest_entry.object_key_id,
                )?;
                let manifest_write = manifest_boundary
                    .encrypt_manifest_locally(manifest_mutation.manifest, manifest_context)?;
                let request = CiphertextGatewayBoundary::delete_ciphertext_request(
                    &preflight.route_plan,
                    &input.envelope_context.bucket_id,
                    manifest_write.encrypted_manifest.ciphertext,
                    current_manifest.encrypted_manifest_reference_hex.clone(),
                )?;

                if manifest_write.encrypted_manifest.gateway_plaintext_access
                    || request.plaintext_payload_present
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                let gateway_response = LocalTrustlessRuntime::execute_prepared_remote_request(
                    runtime_prepared,
                    request,
                    &self.remote_gateway_executor,
                )?;

                self.require_response_action(
                    &gateway_response,
                    RemoteGatewayAction::DeleteCiphertextObject,
                )?;

                if gateway_response.gateway_plaintext_access
                    || prepared.http_response.gateway_plaintext_access
                {
                    return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
                }

                Ok(completed_metadata_http_response(prepared.operation))
            }
            operation => Err(LocalTrustlessExecutionEngineError::UnsupportedOperation(
                operation,
            )),
        }
    }

    fn fetch_and_decrypt_current_manifest(
        &self,
        runtime_prepared: &LocalTrustlessRuntimePreparedResponse,
        envelope_context: &RecipientEnvelopeContext,
    ) -> Result<CurrentTrustlessManifest, LocalTrustlessExecutionEngineError> {
        let bucket = runtime_prepared_bucket(runtime_prepared);
        let route_plan = TrustlessRoutePlanner::plan_list_objects_v2(bucket)?;
        let list_request = CiphertextGatewayBoundary::list_encrypted_manifest_request(
            &route_plan,
            &envelope_context.bucket_id,
        )?;

        let list_response = self.remote_gateway_executor.execute(list_request)?;

        self.require_response_action(&list_response, RemoteGatewayAction::ListCiphertextManifest)?;

        if list_response.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        let Some(ciphertext) = list_response.encrypted_manifest_payload else {
            return Ok(CurrentTrustlessManifest {
                manifest: TrustlessManifest {
                    bucket_id: envelope_context.bucket_id.clone(),
                    manifest_version: 0,
                    entries: Vec::new(),
                },
                encrypted_manifest_reference_hex: None,
            });
        };

        let read = TrustlessManifestBoundary::new(self.manifest_cipher.clone())
            .decrypt_manifest_locally(EncryptedTrustlessManifest {
                ciphertext,
                envelope_context: envelope_context.clone(),
                gateway_plaintext_access: false,
            })?;

        if read.gateway_plaintext_access {
            return Err(LocalTrustlessExecutionEngineError::GatewayPlaintextAccessRejected);
        }

        Ok(CurrentTrustlessManifest {
            manifest: read.manifest,
            encrypted_manifest_reference_hex: list_response.encrypted_manifest_reference_hex,
        })
    }

    fn require_response_action(
        &self,
        response: &crate::gateway_boundary::CiphertextGatewayResponse,
        expected: RemoteGatewayAction,
    ) -> Result<(), LocalTrustlessExecutionEngineError> {
        if response.action != expected {
            return Err(
                LocalTrustlessExecutionEngineError::UnexpectedRemoteResponseAction {
                    expected,
                    actual: response.action,
                },
            );
        }

        Ok(())
    }
}

fn runtime_prepared_bucket(prepared: &LocalTrustlessRuntimePreparedResponse) -> String {
    prepared
        .handler_response
        .request_preparation
        .prepared_operation
        .pipeline_plan
        .request_context
        .preflight_request
        .bucket
        .clone()
}

fn completed_metadata_http_response(operation: LocalS3Operation) -> LocalTrustlessHttpResponse {
    let status_code = match operation {
        LocalS3Operation::DeleteObject => 204,
        LocalS3Operation::HeadObject | LocalS3Operation::ListObjectsV2 => 200,
        LocalS3Operation::PutObject
        | LocalS3Operation::GetObject
        | LocalS3Operation::CreateTrustlessBucket => 200,
    };

    LocalTrustlessHttpResponse {
        status_code,
        body: None,
        headers: vec![
            (
                "x-s3w-trustless-state".to_owned(),
                "ReadyMetadataOnly".to_owned(),
            ),
            (
                "x-s3w-remote-gateway-required".to_owned(),
                "true".to_owned(),
            ),
            (
                "x-s3w-gateway-plaintext-access".to_owned(),
                "false".to_owned(),
            ),
        ],
        metadata_only: true,
        plaintext_returned_locally: false,
        gateway_plaintext_access: false,
    }
}

fn completed_list_http_response(body: Vec<u8>) -> LocalTrustlessHttpResponse {
    LocalTrustlessHttpResponse {
        status_code: 200,
        body: Some(body),
        headers: vec![
            ("content-type".to_owned(), "application/xml".to_owned()),
            (
                "x-s3w-trustless-state".to_owned(),
                "ReadyMetadataOnly".to_owned(),
            ),
            (
                "x-s3w-remote-gateway-required".to_owned(),
                "true".to_owned(),
            ),
            (
                "x-s3w-gateway-plaintext-access".to_owned(),
                "false".to_owned(),
            ),
        ],
        metadata_only: true,
        plaintext_returned_locally: false,
        gateway_plaintext_access: false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalListQuery {
    prefix: Option<String>,
    max_keys: usize,
    continuation_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalListSnapshot {
    bucket_id: String,
    encrypted_manifest_reference_hex: String,
    manifest_version: u64,
    prefix: String,
    after_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalListContinuationTokenPayload {
    schema: String,
    bucket_id: String,
    encrypted_manifest_reference_hex: String,
    manifest_version: u64,
    prefix: String,
    after_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustlessListPage {
    entries: Vec<TrustlessManifestEntry>,
    is_truncated: bool,
    next_after_key: Option<String>,
}

fn parse_local_list_query(
    query: Option<&str>,
) -> Result<LocalListQuery, LocalTrustlessExecutionEngineError> {
    let prefix = query_value(query, "prefix");
    let max_keys = match query_value(query, "max-keys") {
        Some(raw) => raw.parse::<usize>().map_err(|_| {
            LocalTrustlessExecutionEngineError::InvalidListQuery(
                "max-keys must be an unsigned integer".to_owned(),
            )
        })?,
        None => 1000,
    };

    Ok(LocalListQuery {
        prefix,
        max_keys,
        continuation_token: query_value(query, "continuation-token"),
    })
}

fn resolve_local_list_snapshot(
    current_manifest: &CurrentTrustlessManifest,
    bucket_id: &str,
    prefix: &str,
    continuation_token: Option<&str>,
) -> Result<LocalListSnapshot, LocalTrustlessExecutionEngineError> {
    let current_reference = current_manifest
        .encrypted_manifest_reference_hex
        .clone()
        .unwrap_or_default();
    let bucket_id = bucket_id.trim().to_owned();

    let Some(continuation_token) = continuation_token else {
        return Ok(LocalListSnapshot {
            bucket_id,
            encrypted_manifest_reference_hex: current_reference,
            manifest_version: current_manifest.manifest.manifest_version,
            prefix: prefix.to_owned(),
            after_key: None,
        });
    };

    let payload = decode_local_list_continuation_token(continuation_token)?;

    if payload.bucket_id != bucket_id {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "token bucket id does not match request bucket".to_owned(),
            ),
        );
    }

    if payload.prefix != prefix {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "token prefix does not match request prefix".to_owned(),
            ),
        );
    }

    if payload.encrypted_manifest_reference_hex != current_reference {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "encrypted manifest changed since the continuation token was issued".to_owned(),
            ),
        );
    }

    if payload.manifest_version != current_manifest.manifest.manifest_version {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "manifest version changed since the continuation token was issued".to_owned(),
            ),
        );
    }

    Ok(LocalListSnapshot {
        bucket_id,
        encrypted_manifest_reference_hex: payload.encrypted_manifest_reference_hex,
        manifest_version: payload.manifest_version,
        prefix: payload.prefix,
        after_key: Some(payload.after_key),
    })
}

fn encode_local_list_continuation_token(
    snapshot: &LocalListSnapshot,
    after_key: &str,
) -> Result<String, LocalTrustlessExecutionEngineError> {
    let after_key = after_key.trim();

    if after_key.is_empty() {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "continuation after_key is required".to_owned(),
            ),
        );
    }

    let payload = LocalListContinuationTokenPayload {
        schema: LOCAL_LIST_CONTINUATION_TOKEN_PREFIX.to_owned(),
        bucket_id: snapshot.bucket_id.clone(),
        encrypted_manifest_reference_hex: snapshot.encrypted_manifest_reference_hex.clone(),
        manifest_version: snapshot.manifest_version,
        prefix: snapshot.prefix.clone(),
        after_key: after_key.to_owned(),
    };

    let payload_bytes = serde_json::to_vec(&payload).map_err(|error| {
        LocalTrustlessExecutionEngineError::InvalidListContinuationToken(error.to_string())
    })?;

    Ok(format!(
        "{}:{}",
        LOCAL_LIST_CONTINUATION_TOKEN_PREFIX,
        hex::encode(payload_bytes)
    ))
}

fn decode_local_list_continuation_token(
    token: &str,
) -> Result<LocalListContinuationTokenPayload, LocalTrustlessExecutionEngineError> {
    let Some(payload_hex) = token
        .trim()
        .strip_prefix(LOCAL_LIST_CONTINUATION_TOKEN_PREFIX)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "token must be an opaque s3gw-local-list-v1 token".to_owned(),
            ),
        );
    };

    let payload_bytes = hex::decode(payload_hex).map_err(|error| {
        LocalTrustlessExecutionEngineError::InvalidListContinuationToken(error.to_string())
    })?;
    let payload: LocalListContinuationTokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|error| {
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(error.to_string())
        })?;

    if payload.schema != LOCAL_LIST_CONTINUATION_TOKEN_PREFIX {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "token schema is invalid".to_owned(),
            ),
        );
    }

    if payload.after_key.trim().is_empty() {
        return Err(
            LocalTrustlessExecutionEngineError::InvalidListContinuationToken(
                "token after_key is required".to_owned(),
            ),
        );
    }

    Ok(payload)
}

fn page_trustless_list_entries(
    mut entries: Vec<TrustlessManifestEntry>,
    max_keys: usize,
    after_key: Option<&str>,
) -> TrustlessListPage {
    entries.sort_by(|left, right| {
        left.object_key
            .cmp(&right.object_key)
            .then_with(|| left.object_key_id.cmp(&right.object_key_id))
    });

    let mut entries = entries
        .into_iter()
        .filter(|entry| after_key.is_none_or(|after_key| entry.object_key.as_str() > after_key))
        .collect::<Vec<_>>();

    let is_truncated = entries.len() > max_keys;
    let next_after_key = if is_truncated && max_keys > 0 {
        entries
            .get(max_keys - 1)
            .map(|entry| entry.object_key.clone())
    } else {
        None
    };

    entries.truncate(max_keys);

    TrustlessListPage {
        entries,
        is_truncated,
        next_after_key,
    }
}

fn trustless_list_objects_v2_response_body(
    bucket: &str,
    prefix: Option<&str>,
    max_keys: usize,
    continuation_token: Option<&str>,
    is_truncated: bool,
    next_continuation_token: Option<&str>,
    entries: &[TrustlessManifestEntry],
) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    body.push_str(r#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    push_xml_text(&mut body, "Name", bucket);
    push_xml_text(&mut body, "Prefix", prefix.unwrap_or(""));
    push_xml_text(&mut body, "MaxKeys", &max_keys.to_string());
    push_xml_text(&mut body, "KeyCount", &entries.len().to_string());
    push_xml_text(
        &mut body,
        "IsTruncated",
        if is_truncated { "true" } else { "false" },
    );

    if let Some(token) = continuation_token {
        push_xml_text(&mut body, "ContinuationToken", token);
    }

    if let Some(token) = next_continuation_token {
        push_xml_text(&mut body, "NextContinuationToken", token);
    }

    for entry in entries {
        body.push_str("<Contents>");
        push_xml_text(&mut body, "Key", &entry.object_key);
        let etag = entry
            .etag
            .as_deref()
            .map(|etag| format!("\"{etag}\""))
            .unwrap_or_default();
        push_xml_text(&mut body, "ETag", &etag);
        push_xml_text(&mut body, "Size", &entry.ciphertext_size.to_string());
        push_xml_text(&mut body, "StorageClass", "STANDARD");
        body.push_str("</Contents>");
    }

    body.push_str("</ListBucketResult>");
    body.into_bytes()
}

fn push_xml_text(body: &mut String, tag: &str, value: &str) {
    body.push('<');
    body.push_str(tag);
    body.push('>');
    body.push_str(&escape_xml(value));
    body.push_str("</");
    body.push_str(tag);
    body.push('>');
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }

    escaped
}

fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(left, right)| {
            if left == key {
                Some(right.trim().to_owned())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn runtime_prepared_preflight_request(
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> TrustlessPreflightRequest {
    prepared
        .handler_response
        .request_preparation
        .prepared_operation
        .pipeline_plan
        .request_context
        .preflight_request
        .clone()
}

fn runtime_prepared_object_key(
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> Result<String, LocalTrustlessExecutionEngineError> {
    runtime_prepared_preflight_request(prepared)
        .key
        .filter(|object_key| !object_key.trim().is_empty())
        .ok_or(LocalTrustlessExecutionEngineError::MissingPreparedObjectKey)
}

fn runtime_prepared_put_plaintext(
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> Result<Vec<u8>, LocalTrustlessExecutionEngineError> {
    prepared
        .handler_response
        .request_preparation
        .prepared_operation
        .pipeline_plan
        .request_context
        .plaintext_body
        .clone()
        .filter(|body| !body.is_empty())
        .ok_or_else(|| {
            LocalTrustlessExecutionEngineError::Runtime(
                LocalTrustlessRuntimeError::MissingPreparedPutPlaintextBody,
            )
        })
}

fn runtime_prepared_prefix(prepared: &LocalTrustlessRuntimePreparedResponse) -> Option<String> {
    prepared
        .handler_response
        .request_preparation
        .s3_request
        .prefix
        .clone()
}

fn manifest_entry_for_runtime_request(
    manifest: &TrustlessManifest,
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> Result<TrustlessManifestEntry, LocalTrustlessExecutionEngineError> {
    let object_key = runtime_prepared_object_key(prepared)?;

    manifest
        .entries
        .iter()
        .find(|entry| entry.object_key == object_key)
        .cloned()
        .ok_or_else(|| {
            LocalTrustlessExecutionEngineError::Manifest(
                TrustlessManifestError::ManifestEntryNotFound(object_key),
            )
        })
}

fn manifest_envelope_context(context: &RecipientEnvelopeContext) -> RecipientEnvelopeContext {
    let mut manifest_context = context.clone();
    manifest_context.object_key_id = manifest_context.bucket_id.clone();
    manifest_context
}

fn object_envelope_context(
    context: &RecipientEnvelopeContext,
    object_key_id: String,
) -> RecipientEnvelopeContext {
    let mut object_context = context.clone();
    object_context.object_key_id = object_key_id;
    object_context
}

fn fresh_object_context_id_hex() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
    use crate::http_mapping::{
        LocalTrustlessHttpMethod, LocalTrustlessHttpRequest, LocalTrustlessHttpRequestContext,
    };
    use crate::keyring::TrustlessRecipientKeyring;
    use crate::local_keystore::{
        LocalKeystoreError, LocalKeystoreRecord, LocalPrivateKeySelection,
    };
    use crate::manifest::{TrustlessManifest, TrustlessManifestError};
    use crate::planner::RemoteGatewayAction;
    use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord};
    use crate::remote_gateway::{RemoteGatewayClientError, TrustlessRemoteGatewayClient};
    use crate::server::LocalTrustlessServerConfig;
    use crate::types::{RecipientEncryptionKey, SubstrateAccountId};

    #[derive(Debug, Default)]
    struct EngineMockRecipientKeyResolver {
        records: BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl EngineMockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for EngineMockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct EngineMockLocalKeystoreResolver {
        records: BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl EngineMockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for EngineMockLocalKeystoreResolver {
        fn list_local_private_keys(
            &self,
            account: &SubstrateAccountId,
            key_type: &str,
        ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreError> {
            Ok(self
                .records
                .get(&(account.clone(), key_type.to_owned()))
                .cloned()
                .unwrap_or_default())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct EngineMockManifestCipher;

    impl TrustlessManifestCipher for EngineMockManifestCipher {
        fn decrypt_manifest(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            if ciphertext != b"engine-encrypted-manifest" {
                return Err(TrustlessManifestError::Cipher(
                    "unexpected engine encrypted manifest".to_owned(),
                ));
            }

            Ok(engine_manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "engine-encrypted-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    #[derive(Debug, Clone)]
    struct EngineMockRemoteGatewayClient {
        responses: Rc<RefCell<Vec<CiphertextGatewayResponse>>>,
        seen_requests: Rc<RefCell<Vec<CiphertextGatewayRequest>>>,
    }

    impl TrustlessRemoteGatewayClient for EngineMockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            self.seen_requests.borrow_mut().push(request);

            if self.responses.borrow().is_empty() {
                return Err(RemoteGatewayClientError::Http(
                    "engine mock remote gateway response queue is empty".to_owned(),
                ));
            }

            Ok(self.responses.borrow_mut().remove(0))
        }
    }

    type TestEngine = LocalTrustlessExecutionEngine<
        EngineMockManifestCipher,
        EngineMockRecipientKeyResolver,
        EngineMockLocalKeystoreResolver,
        EngineMockRemoteGatewayClient,
    >;

    fn run_openssl(args: &[&str], cwd: &std::path::Path) {
        let output = std::process::Command::new("openssl")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to invoke openssl for engine AWS ESDK Raw RSA test keys");

        assert!(
            output.status.success(),
            "openssl {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn generate_test_rsa_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().expect("failed to create temp dir for RSA test keys");
        let private_key = dir.path().join("private.pem");
        let public_key = dir.path().join("public.pem");

        run_openssl(
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                private_key.file_name().unwrap().to_str().unwrap(),
            ],
            dir.path(),
        );

        run_openssl(
            &[
                "rsa",
                "-in",
                private_key.file_name().unwrap().to_str().unwrap(),
                "-pubout",
                "-out",
                public_key.file_name().unwrap().to_str().unwrap(),
            ],
            dir.path(),
        );

        (
            std::fs::read(private_key).unwrap(),
            std::fs::read(public_key).unwrap(),
        )
    }

    fn server() -> LocalTrustlessServer {
        LocalTrustlessServer::new(LocalTrustlessServerConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            max_request_body_bytes: 1024 * 1024,
            remote_gateway_url: Some("http://127.0.0.1:3000".to_owned()),
            network_bind_enabled: false,
        })
        .unwrap()
    }

    fn proxy_config() -> TrustlessProxyConfig {
        TrustlessProxyConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            remote_gateway_url: "http://127.0.0.1:3000".to_owned(),
            chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
            local_account: "alice".to_owned(),
            keystore_path: std::path::PathBuf::from("./keystore.json"),
            local_private_key_unlock_key: [44u8; 32],
            aws_esdk_key_namespace: "engine-test-namespace".to_owned(),
        }
    }

    fn local_private_key_selection(blob: Vec<u8>) -> LocalPrivateKeySelection {
        LocalPrivateKeySelection {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            encrypted_private_key_blob: blob,
            storage_label: "local-keystore/alice/1".to_owned(),
        }
    }

    fn recipient_record(account: &str, public_key_pem: &[u8]) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn recipient_encryption_key(account: &str, public_key_pem: &[u8]) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn local_record(config: &TrustlessProxyConfig, private_key_pem: &[u8]) -> LocalKeystoreRecord {
        let selection = local_private_key_selection(b"placeholder".to_vec());
        let encrypted_private_key_blob = config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(&selection, private_key_pem)
            .unwrap();

        LocalKeystoreRecord {
            account: selection.account,
            key_type: selection.key_type,
            key_version: selection.key_version,
            encrypted_private_key_blob,
            enabled: true,
            storage_label: selection.storage_label,
        }
    }

    fn preflight_builder(
        config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TrustlessOperationPreflightBuilder<
        EngineMockRecipientKeyResolver,
        EngineMockLocalKeystoreResolver,
    > {
        TrustlessOperationPreflightBuilder::new(
            EngineMockRecipientKeyResolver::default()
                .with_record(recipient_record("alice", public_key_pem))
                .with_record(recipient_record("bob", public_key_pem)),
            EngineMockLocalKeystoreResolver::default()
                .with_record(local_record(config, private_key_pem)),
        )
    }

    fn envelope_context(public_key_pem: &[u8]) -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec![
                recipient_encryption_key("alice", public_key_pem),
                recipient_encryption_key("bob", public_key_pem),
            ],
        }
    }

    fn http_request(
        method: LocalTrustlessHttpMethod,
        body: Option<Vec<u8>>,
    ) -> LocalTrustlessHttpRequest {
        LocalTrustlessHttpRequest {
            method,
            path: "/bucket/secret.txt".to_owned(),
            query: None,
            body,
        }
    }

    fn http_context() -> LocalTrustlessHttpRequestContext {
        LocalTrustlessHttpRequestContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    fn engine_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: vec![engine_manifest_entry()],
        }
    }

    fn engine_manifest_entry() -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: "secret.txt".to_owned(),
            object_key_id: hex::encode([2u8; 32]),
            ciphertext_ref: "12".repeat(32),
            ciphertext_size: 64,
            content_type: Some("text/plain".to_owned()),
            etag: Some("engine-etag".to_owned()),
        }
    }

    fn execution_input(
        method: LocalTrustlessHttpMethod,
        body: Option<Vec<u8>>,
        public_key_pem: &[u8],
    ) -> LocalTrustlessExecutionInput {
        LocalTrustlessExecutionInput {
            http_request: http_request(method, body),
            http_context: http_context(),
            envelope_context: envelope_context(public_key_pem),
        }
    }

    fn test_engine(
        responses: Vec<CiphertextGatewayResponse>,
        seen_requests: Rc<RefCell<Vec<CiphertextGatewayRequest>>>,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TestEngine {
        let config = proxy_config();

        LocalTrustlessExecutionEngine::new(
            server(),
            config.clone(),
            preflight_builder(&config, private_key_pem, public_key_pem),
            EngineMockManifestCipher,
            TrustlessRemoteGatewayExecutor::new(EngineMockRemoteGatewayClient {
                responses: Rc::new(RefCell::new(responses)),
                seen_requests,
            }),
        )
    }

    fn list_manifest_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::ListCiphertextManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(b"engine-encrypted-manifest".to_vec()),
            ciphertext_reference_hex: None,
            encrypted_manifest_reference_hex: Some("ab".repeat(32)),
            metadata_only: false,
            gateway_plaintext_access: false,
        }
    }

    fn put_object_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::PutCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: Some("cd".repeat(32)),
            encrypted_manifest_reference_hex: None,
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn put_manifest_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::PutEncryptedManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            encrypted_manifest_reference_hex: Some("ef".repeat(32)),
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn head_object_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::HeadCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: Some("12".repeat(32)),
            encrypted_manifest_reference_hex: None,
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn delete_object_response() -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action: RemoteGatewayAction::DeleteCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            encrypted_manifest_reference_hex: Some("ef".repeat(32)),
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    fn encrypt_get_fixture(
        private_key_pem: &[u8],
        public_key_pem: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let config = proxy_config();
        let encrypted_private_key_blob = config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(
                &local_private_key_selection(b"placeholder".to_vec()),
                private_key_pem,
            )
            .unwrap();

        let keyring = LocalTrustlessRuntime::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            &config,
            local_private_key_selection(encrypted_private_key_blob),
        )
        .unwrap();

        keyring
            .encrypt_with_recipient_envelopes(plaintext, &envelope_context(public_key_pem))
            .unwrap()
    }

    #[test]
    fn engine_executes_put_as_ciphertext_only_remote_request() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let plaintext = b"engine PUT plaintext must not leave local boundary".to_vec();

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(plaintext.clone()),
                &public_key_pem,
            ))
            .unwrap();

        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 3);

        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());
        assert!(!requests[0].plaintext_payload_present);

        assert_eq!(requests[1].action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!requests[1].plaintext_payload_present);
        assert!(requests[1].encrypted_manifest_payload.is_none());

        let ciphertext = requests[1].ciphertext_payload.clone().unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
        assert!(!String::from_utf8_lossy(&ciphertext)
            .contains("engine PUT plaintext must not leave local boundary"));

        assert_eq!(
            requests[2].action,
            RemoteGatewayAction::PutEncryptedManifest
        );
        assert!(requests[2].ciphertext_payload.is_none());
        assert_eq!(
            requests[2].expected_manifest_reference_hex,
            Some("ab".repeat(32))
        );
        assert!(!requests[2].plaintext_payload_present);

        let encrypted_manifest = requests[2].encrypted_manifest_payload.clone().unwrap();
        assert_eq!(
            encrypted_manifest,
            format!("engine-encrypted-manifest:{}:2", hex::encode([1u8; 32])).into_bytes()
        );
    }

    #[test]
    fn engine_fetches_decrypts_updates_and_persists_manifest_for_put() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"manifest orchestration plaintext".to_vec()),
                &public_key_pem,
            ))
            .unwrap();

        let requests = seen_requests.borrow();
        let actions = requests
            .iter()
            .map(|request| request.action)
            .collect::<Vec<_>>();

        assert_eq!(
            actions,
            vec![
                RemoteGatewayAction::ListCiphertextManifest,
                RemoteGatewayAction::PutCiphertextObject,
                RemoteGatewayAction::PutEncryptedManifest,
            ]
        );

        assert_eq!(requests[0].bucket_id_hex, hex::encode([1u8; 32]));
        assert_eq!(requests[2].bucket_id_hex, hex::encode([1u8; 32]));
        assert!(requests[2].encrypted_manifest_payload.is_some());
        assert_eq!(
            requests[2].expected_manifest_reference_hex,
            Some("ab".repeat(32))
        );
    }

    #[test]
    fn engine_executes_get_as_local_plaintext_response() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let plaintext = b"engine GET plaintext returns only locally".to_vec();
        let ciphertext = encrypt_get_fixture(&private_key_pem, &public_key_pem, &plaintext);

        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(ciphertext),
                    encrypted_manifest_payload: None,
                    ciphertext_reference_hex: Some("cd".repeat(32)),
                    encrypted_manifest_reference_hex: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Get,
                None,
                &public_key_pem,
            ))
            .unwrap();

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, Some(plaintext));
        assert!(response.plaintext_returned_locally);
        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert_eq!(requests[1].action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(requests[1].ciphertext_reference_hex, Some("12".repeat(32)));
        assert!(requests[1].ciphertext_payload.is_none());
        assert!(requests[1].encrypted_manifest_payload.is_none());
        assert!(!requests[1].plaintext_payload_present);
    }

    #[test]
    fn engine_executes_head_with_manifest_ciphertext_reference() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![list_manifest_response(), head_object_response()],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Head,
                None,
                &public_key_pem,
            ))
            .unwrap();

        assert_eq!(response.status_code, 200);
        assert!(response.body.is_none());
        assert!(response.metadata_only);
        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert_eq!(
            requests[1].action,
            RemoteGatewayAction::HeadCiphertextObject
        );
        assert_eq!(requests[1].ciphertext_reference_hex, Some("12".repeat(32)));
        assert!(requests[1].ciphertext_payload.is_none());
        assert!(requests[1].encrypted_manifest_payload.is_none());
        assert!(!requests[1].plaintext_payload_present);
    }

    #[test]
    fn engine_executes_list_from_decrypted_manifest_metadata() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![list_manifest_response()],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let mut input = execution_input(LocalTrustlessHttpMethod::Get, None, &public_key_pem);
        input.http_request.path = "/bucket".to_owned();
        input.http_request.query = Some("list-type=2&prefix=secret".to_owned());
        input.http_context.object_key_id = None;

        let response = engine.execute_http_request(input).unwrap();

        assert_eq!(response.status_code, 200);
        let body = String::from_utf8(response.body.clone().expect("LIST should return XML body"))
            .expect("LIST body should be UTF-8 XML");
        assert!(body.contains("<ListBucketResult"));
        assert!(body.contains("<Key>secret.txt</Key>"));
        assert!(body.contains("<Size>64</Size>"));
        assert!(response.metadata_only);
        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());
        assert!(!requests[0].plaintext_payload_present);
    }

    #[test]
    fn local_list_continuation_token_detects_manifest_drift() {
        let current_manifest = CurrentTrustlessManifest {
            manifest: engine_manifest(),
            encrypted_manifest_reference_hex: Some("ab".repeat(32)),
        };
        let snapshot =
            resolve_local_list_snapshot(&current_manifest, &hex::encode([1u8; 32]), "secret", None)
                .unwrap();
        let token = encode_local_list_continuation_token(&snapshot, "secret.txt").unwrap();

        let advanced_manifest = CurrentTrustlessManifest {
            manifest: TrustlessManifest {
                manifest_version: 2,
                ..engine_manifest()
            },
            encrypted_manifest_reference_hex: Some("cd".repeat(32)),
        };
        let err = resolve_local_list_snapshot(
            &advanced_manifest,
            &hex::encode([1u8; 32]),
            "secret",
            Some(&token),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("encrypted manifest changed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn engine_executes_delete_with_manifest_cas_reference() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![list_manifest_response(), delete_object_response()],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let response = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Delete,
                None,
                &public_key_pem,
            ))
            .unwrap();

        assert_eq!(response.status_code, 204);
        assert!(response.body.is_none());
        assert!(!response.gateway_plaintext_access);

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert_eq!(
            requests[1].action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(requests[1].ciphertext_payload.is_none());
        assert!(requests[1].encrypted_manifest_payload.is_some());
        assert_eq!(
            requests[1].expected_manifest_reference_hex,
            Some("ab".repeat(32))
        );
        assert!(!requests[1].plaintext_payload_present);
    }

    #[test]
    fn engine_rejects_or_fails_closed_if_remote_claims_gateway_plaintext_access() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(b"ciphertext".to_vec()),
                    encrypted_manifest_payload: None,
                    ciphertext_reference_hex: None,
                    encrypted_manifest_reference_hex: None,
                    metadata_only: false,
                    gateway_plaintext_access: true,
                },
            ],
            seen_requests,
            &private_key_pem,
            &public_key_pem,
        );

        let err = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Get,
                None,
                &public_key_pem,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessExecutionEngineError::Runtime(_)
        ));
    }

    #[test]
    fn engine_does_not_send_plaintext_payload_to_remote_gateway() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                list_manifest_response(),
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let plaintext = b"do not send this plaintext remotely".to_vec();

        engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(plaintext.clone()),
                &public_key_pem,
            ))
            .unwrap();

        let requests = seen_requests.borrow();

        for request in requests.iter() {
            assert!(!request.plaintext_payload_present);
        }

        assert!(requests[0].ciphertext_payload.is_none());
        assert!(requests[0].encrypted_manifest_payload.is_none());

        let ciphertext = requests[1].ciphertext_payload.clone().unwrap();
        assert_ne!(ciphertext, plaintext);
        assert!(
            !String::from_utf8_lossy(&ciphertext).contains("do not send this plaintext remotely")
        );

        assert!(requests[2].ciphertext_payload.is_none());
        assert!(requests[2].encrypted_manifest_payload.is_some());
    }

    #[test]
    fn engine_fails_closed_when_manifest_fetch_claims_gateway_plaintext_access() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![CiphertextGatewayResponse {
                action: RemoteGatewayAction::ListCiphertextManifest,
                ciphertext_payload: None,
                encrypted_manifest_payload: Some(b"engine-encrypted-manifest".to_vec()),
                ciphertext_reference_hex: None,
                encrypted_manifest_reference_hex: Some("ab".repeat(32)),
                metadata_only: false,
                gateway_plaintext_access: true,
            }],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        let err = engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"secret".to_vec()),
                &public_key_pem,
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessExecutionEngineError::RemoteGateway(_)
        ));
        assert_eq!(seen_requests.borrow().len(), 1);
        assert_eq!(
            seen_requests.borrow()[0].action,
            RemoteGatewayAction::ListCiphertextManifest
        );
    }

    #[test]
    fn engine_treats_missing_manifest_payload_as_empty_manifest_for_first_put() {
        let (private_key_pem, public_key_pem) = generate_test_rsa_pem_pair();
        let seen_requests = Rc::new(RefCell::new(Vec::new()));
        let engine = test_engine(
            vec![
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::ListCiphertextManifest,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    ciphertext_reference_hex: None,
                    encrypted_manifest_reference_hex: None,
                    metadata_only: true,
                    gateway_plaintext_access: false,
                },
                put_object_response(),
                put_manifest_response(),
            ],
            seen_requests.clone(),
            &private_key_pem,
            &public_key_pem,
        );

        engine
            .execute_http_request(execution_input(
                LocalTrustlessHttpMethod::Put,
                Some(b"secret".to_vec()),
                &public_key_pem,
            ))
            .unwrap();

        let requests = seen_requests.borrow();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2].action,
            RemoteGatewayAction::PutEncryptedManifest
        );
        assert!(requests[2].expected_manifest_reference_hex.is_none());
    }
}
