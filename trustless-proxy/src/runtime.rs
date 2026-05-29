use thiserror::Error;

use crate::aws_esdk::{
    AwsEsdkKeyringConfig, AwsEsdkRawRsaByteCryptoAdapterConfig, AwsEsdkTrustlessRecipientKeyring,
    RealAwsEsdkRawRsaByteCryptoAdapter,
};
use crate::config::{ConfigError, TrustlessProxyConfig};
use crate::encryption::TrustlessEncryptResult;
use crate::execution_coordinator::{
    TrustlessExecutionCoordinator, TrustlessExecutionCoordinatorError,
};
use crate::gateway_boundary::{
    CiphertextGatewayBoundary, CiphertextGatewayBoundaryError, CiphertextGatewayRequest,
    CiphertextGatewayResponse,
};
use crate::handler::{
    LocalTrustlessHandler, LocalTrustlessHandlerCompletion, LocalTrustlessHandlerError,
    LocalTrustlessHandlerPreparedResponse,
};
use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
use crate::local_keystore::{LocalKeystoreResolver, LocalPrivateKeySelection};
use crate::manifest::{TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry};
use crate::operations::{
    TrustlessDeleteOperationInput, TrustlessDeleteOperationPlan, TrustlessOperationAssembler,
    TrustlessOperationError, TrustlessPutOperationInput, TrustlessPutOperationPlan,
};
use crate::planner::{PlannerError, RemoteGatewayAction, TrustlessRoutePlanner};
use crate::preflight::{
    PreflightError, TrustlessOperationPreflightBuilder, TrustlessPreflightRequest,
};
use crate::recipient_keys::RecipientKeyResolver;
use crate::remote_gateway::{
    RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
};
use crate::remote_gateway_http::RemoteGatewayHttpClient;
use crate::request_adapter::LocalTrustlessRequestInput;
use crate::response_adapter::{LocalTrustlessResponseEnvelope, LocalTrustlessResponseState};
use crate::s3_surface::LocalS3Operation;
use crate::types::RecipientEnvelopeContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTrustlessRuntimePhase {
    PreparedPendingResponse,
    CompletedLocalResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessRuntimePreparedResponse {
    pub operation: LocalS3Operation,
    pub handler_response: LocalTrustlessHandlerPreparedResponse,
    pub response_envelope: LocalTrustlessResponseEnvelope,
    pub runtime_phase: LocalTrustlessRuntimePhase,
    pub remote_gateway_required: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessRuntimeCompletion {
    pub operation: LocalS3Operation,
    pub handler_completion: LocalTrustlessHandlerCompletion,
    pub response_envelope: LocalTrustlessResponseEnvelope,
    pub runtime_phase: LocalTrustlessRuntimePhase,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTrustlessRuntimeRemotePayload {
    None,
    PutCiphertext(Vec<u8>),
    DeleteEncryptedManifest(Vec<u8>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessRuntimeError {
    #[error(transparent)]
    Handler(LocalTrustlessHandlerError),

    #[error(transparent)]
    RemoteGateway(RemoteGatewayClientError),

    #[error(transparent)]
    ExecutionCoordinator(TrustlessExecutionCoordinatorError),

    #[error(transparent)]
    GatewayBoundary(CiphertextGatewayBoundaryError),

    #[error(transparent)]
    Planner(PlannerError),

    #[error(transparent)]
    Preflight(PreflightError),

    #[error(transparent)]
    Operation(TrustlessOperationError),

    #[error(transparent)]
    Config(ConfigError),

    #[error(transparent)]
    Keyring(KeyringError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("prepared runtime response does not require remote gateway execution")]
    PreparedResponseDoesNotRequireRemoteGateway,

    #[error("prepared runtime operation mismatch, expected {expected:?}, got {actual:?}")]
    UnexpectedPreparedOperation {
        expected: LocalS3Operation,
        actual: LocalS3Operation,
    },

    #[error("prepared PUT operation is missing local plaintext body")]
    MissingPreparedPutPlaintextBody,

    #[error("prepared PUT remote request requires ciphertext payload")]
    MissingPutCiphertextPayload,

    #[error("prepared DELETE remote request requires encrypted manifest payload")]
    MissingDeleteEncryptedManifestPayload,

    #[error("prepared remote request payload is not valid for operation {operation:?}")]
    UnexpectedRemotePayloadForOperation { operation: LocalS3Operation },

    #[error("operation plan does not keep remote payloads ciphertext-only")]
    OperationPlanAllowsNonCiphertextRemotePayload,

    #[error("operation plan remote action mismatch, expected {expected:?}, got {actual:?}")]
    OperationPlanRemoteActionMismatch {
        expected: RemoteGatewayAction,
        actual: RemoteGatewayAction,
    },

    #[error("prepared remote request is missing object key id")]
    PreparedRemoteRequestMissingObjectKeyId,

    #[error("prepared runtime response is not a pending GET local decrypt")]
    PreparedResponseIsNotPendingGetDecrypt,
}

impl From<LocalTrustlessHandlerError> for LocalTrustlessRuntimeError {
    fn from(error: LocalTrustlessHandlerError) -> Self {
        Self::Handler(error)
    }
}

impl From<RemoteGatewayClientError> for LocalTrustlessRuntimeError {
    fn from(error: RemoteGatewayClientError) -> Self {
        Self::RemoteGateway(error)
    }
}

impl From<TrustlessExecutionCoordinatorError> for LocalTrustlessRuntimeError {
    fn from(error: TrustlessExecutionCoordinatorError) -> Self {
        Self::ExecutionCoordinator(error)
    }
}

impl From<CiphertextGatewayBoundaryError> for LocalTrustlessRuntimeError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::GatewayBoundary(error)
    }
}

impl From<PlannerError> for LocalTrustlessRuntimeError {
    fn from(error: PlannerError) -> Self {
        Self::Planner(error)
    }
}

impl From<PreflightError> for LocalTrustlessRuntimeError {
    fn from(error: PreflightError) -> Self {
        Self::Preflight(error)
    }
}

impl From<TrustlessOperationError> for LocalTrustlessRuntimeError {
    fn from(error: TrustlessOperationError) -> Self {
        Self::Operation(error)
    }
}

impl From<ConfigError> for LocalTrustlessRuntimeError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<KeyringError> for LocalTrustlessRuntimeError {
    fn from(error: KeyringError) -> Self {
        Self::Keyring(error)
    }
}

pub struct LocalTrustlessRuntime;

impl LocalTrustlessRuntime {
    pub fn prepare_request(
        input: LocalTrustlessRequestInput,
    ) -> Result<LocalTrustlessRuntimePreparedResponse, LocalTrustlessRuntimeError> {
        let handler_response = LocalTrustlessHandler::prepare_request(input)?;

        if handler_response.gateway_plaintext_access
            || handler_response.response_envelope.gateway_plaintext_access
        {
            return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
        }

        let operation = handler_response.operation;
        let response_envelope = handler_response.response_envelope.clone();
        let remote_gateway_required = response_envelope.remote_gateway_required;

        Ok(LocalTrustlessRuntimePreparedResponse {
            operation,
            handler_response,
            response_envelope,
            runtime_phase: LocalTrustlessRuntimePhase::PreparedPendingResponse,
            remote_gateway_required,
            gateway_plaintext_access: false,
        })
    }

    pub fn build_prepared_remote_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        payload: LocalTrustlessRuntimeRemotePayload,
    ) -> Result<CiphertextGatewayRequest, LocalTrustlessRuntimeError> {
        validate_prepared_remote_execution(prepared)?;

        let preflight_request = &prepared
            .handler_response
            .request_preparation
            .prepared_operation
            .pipeline_plan
            .request_context
            .preflight_request;

        match prepared.operation {
            LocalS3Operation::PutObject => {
                let ciphertext = match payload {
                    LocalTrustlessRuntimeRemotePayload::PutCiphertext(ciphertext)
                        if !ciphertext.is_empty() =>
                    {
                        ciphertext
                    }
                    LocalTrustlessRuntimeRemotePayload::PutCiphertext(_)
                    | LocalTrustlessRuntimeRemotePayload::None => {
                        return Err(LocalTrustlessRuntimeError::MissingPutCiphertextPayload);
                    }
                    LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(_) => {
                        return Err(
                            LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation {
                                operation: prepared.operation,
                            },
                        );
                    }
                };

                let envelope_context = recipient_envelope_context(preflight_request)?;
                let route_plan = TrustlessRoutePlanner::plan_put_object(
                    preflight_request.bucket.clone(),
                    preflight_request.key.clone().unwrap_or_default(),
                    Some(&envelope_context),
                )?;

                Ok(CiphertextGatewayBoundary::put_ciphertext_request(
                    &route_plan,
                    TrustlessEncryptResult {
                        ciphertext,
                        envelope_context,
                        remote_payload_is_ciphertext_only: true,
                        gateway_plaintext_access: false,
                    },
                )?)
            }
            LocalS3Operation::GetObject => {
                require_no_remote_payload(prepared.operation, payload)?;

                let route_plan = TrustlessRoutePlanner::plan_get_object(
                    preflight_request.bucket.clone(),
                    preflight_request.key.clone().unwrap_or_default(),
                )?;

                Ok(CiphertextGatewayBoundary::get_ciphertext_request(
                    &route_plan,
                )?)
            }
            LocalS3Operation::HeadObject => {
                require_no_remote_payload(prepared.operation, payload)?;

                let route_plan = TrustlessRoutePlanner::plan_head_object(
                    preflight_request.bucket.clone(),
                    preflight_request.key.clone().unwrap_or_default(),
                )?;

                Ok(CiphertextGatewayBoundary::head_ciphertext_request(
                    &route_plan,
                )?)
            }
            LocalS3Operation::ListObjectsV2 => {
                require_no_remote_payload(prepared.operation, payload)?;

                let route_plan =
                    TrustlessRoutePlanner::plan_list_objects_v2(preflight_request.bucket.clone())?;

                Ok(CiphertextGatewayBoundary::list_encrypted_manifest_request(
                    &route_plan,
                )?)
            }
            LocalS3Operation::DeleteObject => {
                let encrypted_manifest = match payload {
                    LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(
                        encrypted_manifest,
                    ) if !encrypted_manifest.is_empty() => encrypted_manifest,
                    LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(_)
                    | LocalTrustlessRuntimeRemotePayload::None => {
                        return Err(
                            LocalTrustlessRuntimeError::MissingDeleteEncryptedManifestPayload,
                        );
                    }
                    LocalTrustlessRuntimeRemotePayload::PutCiphertext(_) => {
                        return Err(
                            LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation {
                                operation: prepared.operation,
                            },
                        );
                    }
                };

                let route_plan = TrustlessRoutePlanner::plan_delete_object(
                    preflight_request.bucket.clone(),
                    preflight_request.key.clone().unwrap_or_default(),
                )?;

                Ok(CiphertextGatewayBoundary::delete_ciphertext_request(
                    &route_plan,
                    encrypted_manifest,
                )?)
            }
            LocalS3Operation::CreateTrustlessBucket => {
                Err(LocalTrustlessRuntimeError::PreparedResponseDoesNotRequireRemoteGateway)
            }
        }
    }

    pub fn build_prepared_put_operation_plan<K, C, RK, LK>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_entry: TrustlessManifestEntry,
        manifest_envelope_context: RecipientEnvelopeContext,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        assembler: &TrustlessOperationAssembler<K, C>,
    ) -> Result<TrustlessPutOperationPlan, LocalTrustlessRuntimeError>
    where
        K: TrustlessRecipientKeyring,
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_remote_execution(prepared)?;
        require_prepared_operation(prepared, LocalS3Operation::PutObject)?;

        let plaintext = prepared
            .handler_response
            .request_preparation
            .prepared_operation
            .pipeline_plan
            .request_context
            .plaintext_body
            .clone()
            .filter(|body| !body.is_empty())
            .ok_or(LocalTrustlessRuntimeError::MissingPreparedPutPlaintextBody)?;

        let preflight =
            preflight_builder.preflight_put_object(prepared_preflight_request(prepared).clone())?;

        Ok(assembler.prepare_put(TrustlessPutOperationInput {
            plaintext,
            preflight,
            current_manifest,
            manifest_entry,
            manifest_envelope_context,
        })?)
    }

    pub fn build_prepared_delete_operation_plan<K, C, RK, LK>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_envelope_context: RecipientEnvelopeContext,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        assembler: &TrustlessOperationAssembler<K, C>,
    ) -> Result<TrustlessDeleteOperationPlan, LocalTrustlessRuntimeError>
    where
        K: TrustlessRecipientKeyring,
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_remote_execution(prepared)?;
        require_prepared_operation(prepared, LocalS3Operation::DeleteObject)?;

        let preflight_request = prepared_preflight_request(prepared);
        let object_key_id = preflight_request
            .object_key_id
            .clone()
            .filter(|object_key_id| !object_key_id.trim().is_empty())
            .ok_or(LocalTrustlessRuntimeError::PreparedRemoteRequestMissingObjectKeyId)?;

        let preflight = preflight_builder.preflight_delete_object(preflight_request.clone())?;

        Ok(assembler.prepare_delete(TrustlessDeleteOperationInput {
            preflight,
            current_manifest,
            object_key_id,
            manifest_envelope_context,
        })?)
    }

    pub fn execute_prepared_put_operation<K, C, RK, LK, G>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_entry: TrustlessManifestEntry,
        manifest_envelope_context: RecipientEnvelopeContext,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        assembler: &TrustlessOperationAssembler<K, C>,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        K: TrustlessRecipientKeyring,
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        let plan = Self::build_prepared_put_operation_plan(
            prepared,
            current_manifest,
            manifest_entry,
            manifest_envelope_context,
            preflight_builder,
            assembler,
        )?;

        Self::execute_prepared_put_operation_remote_request(prepared, plan, executor)
    }

    pub fn execute_prepared_delete_operation<K, C, RK, LK, G>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_envelope_context: RecipientEnvelopeContext,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        assembler: &TrustlessOperationAssembler<K, C>,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        K: TrustlessRecipientKeyring,
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        let plan = Self::build_prepared_delete_operation_plan(
            prepared,
            current_manifest,
            manifest_envelope_context,
            preflight_builder,
            assembler,
        )?;

        Self::execute_prepared_delete_operation_remote_request(prepared, plan, executor)
    }

    pub fn build_prepared_put_operation_plan_with_configured_aws_esdk<C, RK, LK>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_entry: TrustlessManifestEntry,
        manifest_envelope_context: RecipientEnvelopeContext,
        config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
    ) -> Result<TrustlessPutOperationPlan, LocalTrustlessRuntimeError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_remote_execution(prepared)?;
        require_prepared_operation(prepared, LocalS3Operation::PutObject)?;

        let plaintext = prepared
            .handler_response
            .request_preparation
            .prepared_operation
            .pipeline_plan
            .request_context
            .plaintext_body
            .clone()
            .filter(|body| !body.is_empty())
            .ok_or(LocalTrustlessRuntimeError::MissingPreparedPutPlaintextBody)?;

        let preflight =
            preflight_builder.preflight_put_object(prepared_preflight_request(prepared).clone())?;

        let keyring = Self::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            config,
            preflight.local_private_key.clone(),
        )?;

        let assembler = TrustlessOperationAssembler::new(keyring, manifest_cipher);

        Ok(assembler.prepare_put(TrustlessPutOperationInput {
            plaintext,
            preflight,
            current_manifest,
            manifest_entry,
            manifest_envelope_context,
        })?)
    }

    pub fn build_prepared_delete_operation_plan_with_configured_aws_esdk<C, RK, LK>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_envelope_context: RecipientEnvelopeContext,
        config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
    ) -> Result<TrustlessDeleteOperationPlan, LocalTrustlessRuntimeError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_remote_execution(prepared)?;
        require_prepared_operation(prepared, LocalS3Operation::DeleteObject)?;

        let preflight_request = prepared_preflight_request(prepared);
        let object_key_id = preflight_request
            .object_key_id
            .clone()
            .filter(|object_key_id| !object_key_id.trim().is_empty())
            .ok_or(LocalTrustlessRuntimeError::PreparedRemoteRequestMissingObjectKeyId)?;

        let preflight = preflight_builder.preflight_delete_object(preflight_request.clone())?;

        let keyring = Self::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            config,
            preflight.local_private_key.clone(),
        )?;

        let assembler = TrustlessOperationAssembler::new(keyring, manifest_cipher);

        Ok(assembler.prepare_delete(TrustlessDeleteOperationInput {
            preflight,
            current_manifest,
            object_key_id,
            manifest_envelope_context,
        })?)
    }

    pub fn execute_prepared_put_operation_with_configured_aws_esdk<C, RK, LK, G>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_entry: TrustlessManifestEntry,
        manifest_envelope_context: RecipientEnvelopeContext,
        config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        let plan = Self::build_prepared_put_operation_plan_with_configured_aws_esdk(
            prepared,
            current_manifest,
            manifest_entry,
            manifest_envelope_context,
            config,
            preflight_builder,
            manifest_cipher,
        )?;

        Self::execute_prepared_put_operation_remote_request(prepared, plan, executor)
    }

    pub fn execute_prepared_delete_operation_with_configured_aws_esdk<C, RK, LK, G>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        current_manifest: TrustlessManifest,
        manifest_envelope_context: RecipientEnvelopeContext,
        config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
        executor: &TrustlessRemoteGatewayExecutor<G>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
        G: TrustlessRemoteGatewayClient,
    {
        let plan = Self::build_prepared_delete_operation_plan_with_configured_aws_esdk(
            prepared,
            current_manifest,
            manifest_envelope_context,
            config,
            preflight_builder,
            manifest_cipher,
        )?;

        Self::execute_prepared_delete_operation_remote_request(prepared, plan, executor)
    }

    pub fn complete_prepared_get_response_with_configured_aws_esdk<C, RK, LK>(
        prepared: LocalTrustlessRuntimePreparedResponse,
        response: CiphertextGatewayResponse,
        envelope_context: RecipientEnvelopeContext,
        config: &TrustlessProxyConfig,
        preflight_builder: &TrustlessOperationPreflightBuilder<RK, LK>,
        manifest_cipher: C,
    ) -> Result<LocalTrustlessRuntimeCompletion, LocalTrustlessRuntimeError>
    where
        C: TrustlessManifestCipher,
        RK: RecipientKeyResolver,
        LK: LocalKeystoreResolver,
    {
        validate_prepared_remote_execution(&prepared)?;
        require_prepared_operation(&prepared, LocalS3Operation::GetObject)?;

        let preflight = preflight_builder
            .preflight_get_object(prepared_preflight_request(&prepared).clone())?;

        let keyring = Self::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            config,
            preflight.local_private_key.clone(),
        )?;

        let assembler = TrustlessOperationAssembler::new(keyring, manifest_cipher);
        let decrypted = assembler.complete_get_response(preflight, response, envelope_context)?;

        Self::complete_get_with_plaintext(prepared, decrypted.plaintext)
    }

    pub fn put_operation_plan_remote_payload(
        plan: TrustlessPutOperationPlan,
    ) -> Result<LocalTrustlessRuntimeRemotePayload, LocalTrustlessRuntimeError> {
        put_operation_plan_payload(plan)
    }

    pub fn delete_operation_plan_remote_payload(
        plan: TrustlessDeleteOperationPlan,
    ) -> Result<LocalTrustlessRuntimeRemotePayload, LocalTrustlessRuntimeError> {
        delete_operation_plan_payload(plan)
    }

    pub fn build_prepared_put_operation_remote_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessPutOperationPlan,
    ) -> Result<CiphertextGatewayRequest, LocalTrustlessRuntimeError> {
        let payload = Self::put_operation_plan_remote_payload(plan)?;
        Self::build_prepared_remote_request(prepared, payload)
    }

    pub fn build_prepared_delete_operation_remote_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessDeleteOperationPlan,
    ) -> Result<CiphertextGatewayRequest, LocalTrustlessRuntimeError> {
        let payload = Self::delete_operation_plan_remote_payload(plan)?;
        Self::build_prepared_remote_request(prepared, payload)
    }

    pub fn execute_prepared_put_operation_remote_request<C>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessPutOperationPlan,
        executor: &TrustlessRemoteGatewayExecutor<C>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessRemoteGatewayClient,
    {
        let request = Self::build_prepared_put_operation_remote_request(prepared, plan)?;
        Self::execute_prepared_remote_request(prepared, request, executor)
    }

    pub fn execute_prepared_delete_operation_remote_request<C>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessDeleteOperationPlan,
        executor: &TrustlessRemoteGatewayExecutor<C>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessRemoteGatewayClient,
    {
        let request = Self::build_prepared_delete_operation_remote_request(prepared, plan)?;
        Self::execute_prepared_remote_request(prepared, request, executor)
    }

    pub fn execute_prepared_put_operation_remote_http_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessPutOperationPlan,
        config: &TrustlessProxyConfig,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError> {
        let request = Self::build_prepared_put_operation_remote_request(prepared, plan)?;
        Self::execute_prepared_remote_http_request(prepared, request, config)
    }

    pub fn execute_prepared_delete_operation_remote_http_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        plan: TrustlessDeleteOperationPlan,
        config: &TrustlessProxyConfig,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError> {
        let request = Self::build_prepared_delete_operation_remote_request(prepared, plan)?;
        Self::execute_prepared_remote_http_request(prepared, request, config)
    }

    pub fn execute_assembled_prepared_remote_request<C>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        payload: LocalTrustlessRuntimeRemotePayload,
        executor: &TrustlessRemoteGatewayExecutor<C>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessRemoteGatewayClient,
    {
        let request = Self::build_prepared_remote_request(prepared, payload)?;
        Self::execute_prepared_remote_request(prepared, request, executor)
    }

    pub fn execute_assembled_prepared_remote_http_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        payload: LocalTrustlessRuntimeRemotePayload,
        config: &TrustlessProxyConfig,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError> {
        let request = Self::build_prepared_remote_request(prepared, payload)?;
        Self::execute_prepared_remote_http_request(prepared, request, config)
    }

    pub fn execute_prepared_remote_request<C>(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        request: CiphertextGatewayRequest,
        executor: &TrustlessRemoteGatewayExecutor<C>,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError>
    where
        C: TrustlessRemoteGatewayClient,
    {
        validate_prepared_remote_execution(prepared)?;

        let response = executor.execute(request)?;
        let response = TrustlessExecutionCoordinator::validate_remote_gateway_response(
            &prepared
                .handler_response
                .request_preparation
                .prepared_operation
                .pipeline_plan,
            response,
        )?;

        if response.gateway_plaintext_access {
            return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
        }

        Ok(response)
    }

    pub fn execute_prepared_remote_http_request(
        prepared: &LocalTrustlessRuntimePreparedResponse,
        request: CiphertextGatewayRequest,
        config: &TrustlessProxyConfig,
    ) -> Result<CiphertextGatewayResponse, LocalTrustlessRuntimeError> {
        let client = RemoteGatewayHttpClient::new(config.remote_gateway_url.clone())
            .map_err(RemoteGatewayClientError::from)?;
        let executor = TrustlessRemoteGatewayExecutor::new(client);

        Self::execute_prepared_remote_request(prepared, request, &executor)
    }

    pub fn build_aws_esdk_raw_rsa_adapter_config_from_local_selection(
        config: &TrustlessProxyConfig,
        selection: LocalPrivateKeySelection,
    ) -> Result<AwsEsdkRawRsaByteCryptoAdapterConfig, LocalTrustlessRuntimeError> {
        let unlocker = config.local_private_key_unlocker();

        Ok(
            AwsEsdkRawRsaByteCryptoAdapterConfig::from_local_private_key_selection_with_namespace(
                selection,
                config.aws_esdk_key_namespace.clone(),
                &unlocker,
            )?,
        )
    }

    pub fn build_aws_esdk_raw_rsa_keyring_from_local_selection(
        config: &TrustlessProxyConfig,
        selection: LocalPrivateKeySelection,
    ) -> Result<
        AwsEsdkTrustlessRecipientKeyring<RealAwsEsdkRawRsaByteCryptoAdapter>,
        LocalTrustlessRuntimeError,
    > {
        let adapter_config =
            Self::build_aws_esdk_raw_rsa_adapter_config_from_local_selection(config, selection)?;

        Ok(AwsEsdkTrustlessRecipientKeyring::with_adapter(
            AwsEsdkKeyringConfig::default(),
            RealAwsEsdkRawRsaByteCryptoAdapter::new(adapter_config),
        ))
    }

    pub fn complete_get_with_plaintext(
        prepared: LocalTrustlessRuntimePreparedResponse,
        plaintext: Vec<u8>,
    ) -> Result<LocalTrustlessRuntimeCompletion, LocalTrustlessRuntimeError> {
        if prepared.gateway_plaintext_access
            || prepared.handler_response.gateway_plaintext_access
            || prepared.response_envelope.gateway_plaintext_access
        {
            return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
        }

        if prepared.operation != LocalS3Operation::GetObject
            || prepared.response_envelope.state != LocalTrustlessResponseState::PendingLocalDecrypt
        {
            return Err(LocalTrustlessRuntimeError::PreparedResponseIsNotPendingGetDecrypt);
        }

        let handler_completion = LocalTrustlessHandler::complete_get_with_plaintext(
            prepared
                .handler_response
                .request_preparation
                .prepared_operation,
            plaintext,
        )?;

        if handler_completion.gateway_plaintext_access
            || handler_completion
                .response_envelope
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
        }

        let operation = handler_completion.operation;
        let response_envelope = handler_completion.response_envelope.clone();

        Ok(LocalTrustlessRuntimeCompletion {
            operation,
            handler_completion,
            response_envelope,
            runtime_phase: LocalTrustlessRuntimePhase::CompletedLocalResponse,
            gateway_plaintext_access: false,
        })
    }
}

fn require_prepared_operation(
    prepared: &LocalTrustlessRuntimePreparedResponse,
    expected: LocalS3Operation,
) -> Result<(), LocalTrustlessRuntimeError> {
    if prepared.operation != expected {
        return Err(LocalTrustlessRuntimeError::UnexpectedPreparedOperation {
            expected,
            actual: prepared.operation,
        });
    }

    Ok(())
}

fn prepared_preflight_request(
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> &TrustlessPreflightRequest {
    &prepared
        .handler_response
        .request_preparation
        .prepared_operation
        .pipeline_plan
        .request_context
        .preflight_request
}

fn put_operation_plan_payload(
    plan: TrustlessPutOperationPlan,
) -> Result<LocalTrustlessRuntimeRemotePayload, LocalTrustlessRuntimeError> {
    validate_operation_plan_remote_boundary(
        RemoteGatewayAction::PutCiphertextObject,
        plan.object_request.action,
        plan.remote_payloads_are_ciphertext_only,
        plan.gateway_plaintext_access
            || plan.object_request.plaintext_payload_present
            || plan.encrypted_manifest.gateway_plaintext_access,
    )?;

    if plan.object_request.encrypted_manifest_payload.is_some() {
        return Err(
            LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation {
                operation: LocalS3Operation::PutObject,
            },
        );
    }

    let Some(ciphertext) = plan.object_request.ciphertext_payload else {
        return Err(LocalTrustlessRuntimeError::MissingPutCiphertextPayload);
    };

    if ciphertext.is_empty() {
        return Err(LocalTrustlessRuntimeError::MissingPutCiphertextPayload);
    }

    Ok(LocalTrustlessRuntimeRemotePayload::PutCiphertext(
        ciphertext,
    ))
}

fn delete_operation_plan_payload(
    plan: TrustlessDeleteOperationPlan,
) -> Result<LocalTrustlessRuntimeRemotePayload, LocalTrustlessRuntimeError> {
    validate_operation_plan_remote_boundary(
        RemoteGatewayAction::DeleteCiphertextObject,
        plan.delete_request.action,
        plan.remote_payloads_are_ciphertext_only,
        plan.gateway_plaintext_access
            || plan.delete_request.plaintext_payload_present
            || plan.encrypted_manifest.gateway_plaintext_access,
    )?;

    if plan.delete_request.ciphertext_payload.is_some() {
        return Err(
            LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation {
                operation: LocalS3Operation::DeleteObject,
            },
        );
    }

    let Some(encrypted_manifest) = plan.delete_request.encrypted_manifest_payload else {
        return Err(LocalTrustlessRuntimeError::MissingDeleteEncryptedManifestPayload);
    };

    if encrypted_manifest.is_empty() {
        return Err(LocalTrustlessRuntimeError::MissingDeleteEncryptedManifestPayload);
    }

    Ok(LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(
        encrypted_manifest,
    ))
}

fn validate_operation_plan_remote_boundary(
    expected: RemoteGatewayAction,
    actual: RemoteGatewayAction,
    remote_payloads_are_ciphertext_only: bool,
    gateway_plaintext_access: bool,
) -> Result<(), LocalTrustlessRuntimeError> {
    if gateway_plaintext_access {
        return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
    }

    if !remote_payloads_are_ciphertext_only {
        return Err(LocalTrustlessRuntimeError::OperationPlanAllowsNonCiphertextRemotePayload);
    }

    if actual != expected {
        return Err(
            LocalTrustlessRuntimeError::OperationPlanRemoteActionMismatch { expected, actual },
        );
    }

    Ok(())
}

fn require_no_remote_payload(
    operation: LocalS3Operation,
    payload: LocalTrustlessRuntimeRemotePayload,
) -> Result<(), LocalTrustlessRuntimeError> {
    match payload {
        LocalTrustlessRuntimeRemotePayload::None => Ok(()),
        LocalTrustlessRuntimeRemotePayload::PutCiphertext(_)
        | LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(_) => {
            Err(LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation { operation })
        }
    }
}

fn recipient_envelope_context(
    request: &TrustlessPreflightRequest,
) -> Result<RecipientEnvelopeContext, LocalTrustlessRuntimeError> {
    let object_key_id = request
        .object_key_id
        .clone()
        .filter(|object_key_id| !object_key_id.trim().is_empty())
        .ok_or(LocalTrustlessRuntimeError::PreparedRemoteRequestMissingObjectKeyId)?;

    Ok(RecipientEnvelopeContext {
        bucket_id: request.bucket_id.clone(),
        object_key_id,
        policy_version: request.policy_version,
        recipients: Vec::new(),
    })
}

fn validate_prepared_remote_execution(
    prepared: &LocalTrustlessRuntimePreparedResponse,
) -> Result<(), LocalTrustlessRuntimeError> {
    if prepared.gateway_plaintext_access
        || prepared.handler_response.gateway_plaintext_access
        || prepared.response_envelope.gateway_plaintext_access
    {
        return Err(LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected);
    }

    if !prepared.remote_gateway_required
        || !prepared.response_envelope.remote_gateway_required
        || !prepared
            .handler_response
            .request_preparation
            .prepared_operation
            .remote_gateway_required
    {
        return Err(LocalTrustlessRuntimeError::PreparedResponseDoesNotRequireRemoteGateway);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_keystore::{LocalKeystoreError, LocalKeystoreRecord};
    use crate::manifest::TrustlessManifestError;
    use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord};
    use crate::request_adapter::LocalTrustlessRequestInput;
    use crate::response_adapter::LocalTrustlessResponseState;
    use crate::service::TrustlessLocalServiceNextAction;
    use crate::types::{RecipientEncryptionKey, SubstrateAccountId};

    fn request_input(operation: LocalS3Operation) -> LocalTrustlessRequestInput {
        LocalTrustlessRequestInput {
            operation,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: None,
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    #[test]
    fn runtime_prepares_put_as_pending_ciphertext_remote_response() {
        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::PutObject);
        assert_eq!(
            prepared.runtime_phase,
            LocalTrustlessRuntimePhase::PreparedPendingResponse
        );
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(prepared.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn runtime_prepares_get_as_pending_local_decrypt_response() {
        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::GetObject);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingLocalDecrypt
        );
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally)
        );
        assert!(prepared.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn runtime_completes_get_as_ready_local_plaintext_response() {
        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let completion =
            LocalTrustlessRuntime::complete_get_with_plaintext(prepared, b"secret".to_vec())
                .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
        assert_eq!(
            completion.runtime_phase,
            LocalTrustlessRuntimePhase::CompletedLocalResponse
        );
        assert_eq!(
            completion.response_envelope.state,
            LocalTrustlessResponseState::ReadyLocalPlaintext
        );
        assert_eq!(completion.response_envelope.status_code, 200);
        assert_eq!(completion.response_envelope.body, Some(b"secret".to_vec()));
        assert!(completion.response_envelope.plaintext_returned_locally);
        assert!(!completion.gateway_plaintext_access);
    }

    #[test]
    fn runtime_prepares_delete_as_pending_ciphertext_remote_response() {
        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::DeleteObject);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert!(prepared.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn runtime_prepares_list_without_object_key_id() {
        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            operation: LocalS3Operation::ListObjectsV2,
            key: None,
            prefix: Some("docs/".to_owned()),
            object_key_id: None,
            ..request_input(LocalS3Operation::ListObjectsV2)
        })
        .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::ListObjectsV2);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert!(prepared.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn runtime_prepares_create_bucket_as_pending_anchor_response() {
        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            operation: LocalS3Operation::CreateTrustlessBucket,
            key: None,
            object_key_id: None,
            ..request_input(LocalS3Operation::CreateTrustlessBucket)
        })
        .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::CreateTrustlessBucket);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingTrustlessBucketAnchor
        );
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor)
        );
        assert!(!prepared.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn runtime_rejects_plaintext_body_outside_put_boundary() {
        let err = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"bad".to_vec()),
            ..request_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessRuntimeError::Handler(_)));
    }

    #[test]
    fn runtime_rejects_completing_non_get_as_plaintext() {
        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let err = LocalTrustlessRuntime::complete_get_with_plaintext(prepared, b"secret".to_vec())
            .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::PreparedResponseIsNotPendingGetDecrypt
        );
    }

    #[test]
    fn runtime_executes_prepared_remote_request_through_executor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            response: CiphertextGatewayResponse,
            seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                *self.seen_request.borrow_mut() = Some(request);
                Ok(self.response.clone())
            }
        }

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let seen_request = Rc::new(RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(b"ciphertext".to_vec()),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let response = LocalTrustlessRuntime::execute_prepared_remote_request(
            &prepared,
            CiphertextGatewayRequest {
                bucket: "bucket".to_owned(),
                key: Some("secret.txt".to_owned()),
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                plaintext_payload_present: false,
            },
            &executor,
        )
        .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(response.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(!response.gateway_plaintext_access);

        let seen_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            seen_request.action,
            RemoteGatewayAction::GetCiphertextObject
        );
        assert!(!seen_request.plaintext_payload_present);
        assert!(seen_request.ciphertext_payload.is_none());
        assert!(seen_request.encrypted_manifest_payload.is_none());
    }

    #[test]
    fn runtime_rejects_remote_response_action_mismatch() {
        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            response: CiphertextGatewayResponse,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                _request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                Ok(self.response.clone())
            }
        }

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
        });

        let err = LocalTrustlessRuntime::execute_prepared_remote_request(
            &prepared,
            CiphertextGatewayRequest {
                bucket: "bucket".to_owned(),
                key: Some("secret.txt".to_owned()),
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                plaintext_payload_present: false,
            },
            &executor,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessRuntimeError::ExecutionCoordinator(
                TrustlessExecutionCoordinatorError::RemoteActionMismatch { .. }
            )
        ));
    }

    #[test]
    fn runtime_rejects_remote_execution_when_prepared_response_does_not_require_gateway() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                *self.seen_request.borrow_mut() = Some(request);
                Ok(CiphertextGatewayResponse {
                    action: RemoteGatewayAction::CreateTrustlessBucket,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    metadata_only: true,
                    gateway_plaintext_access: false,
                })
            }
        }

        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            operation: LocalS3Operation::CreateTrustlessBucket,
            key: None,
            object_key_id: None,
            ..request_input(LocalS3Operation::CreateTrustlessBucket)
        })
        .unwrap();

        let seen_request = Rc::new(RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            seen_request: seen_request.clone(),
        });

        let err = LocalTrustlessRuntime::execute_prepared_remote_request(
            &prepared,
            CiphertextGatewayRequest {
                bucket: "bucket".to_owned(),
                key: None,
                action: RemoteGatewayAction::CreateTrustlessBucket,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                plaintext_payload_present: false,
            },
            &executor,
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::PreparedResponseDoesNotRequireRemoteGateway
        );
        assert!(seen_request.borrow().is_none());
    }

    fn trustless_proxy_config() -> TrustlessProxyConfig {
        TrustlessProxyConfig {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 9090,
            remote_gateway_url: "http://127.0.0.1:3000".to_owned(),
            chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
            local_account: "alice".to_owned(),
            keystore_path: std::path::PathBuf::from("./keystore.json"),
            local_private_key_unlock_key: [12u8; 32],
            aws_esdk_key_namespace: "runtime-config-namespace".to_owned(),
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

    #[test]
    fn runtime_builds_aws_esdk_raw_rsa_adapter_config_from_config_and_keystore_unlock() {
        let config = trustless_proxy_config();
        let private_key_pem =
            b"-----BEGIN PRIVATE KEY-----\nruntime local key\n-----END PRIVATE KEY-----\n".to_vec();

        let encrypted_private_key_blob = config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(
                &local_private_key_selection(b"placeholder".to_vec()),
                &private_key_pem,
            )
            .unwrap();

        let adapter_config =
            LocalTrustlessRuntime::build_aws_esdk_raw_rsa_adapter_config_from_local_selection(
                &config,
                local_private_key_selection(encrypted_private_key_blob),
            )
            .unwrap();

        assert_eq!(adapter_config.key_namespace, "runtime-config-namespace");
        assert_eq!(
            adapter_config.local_key_name,
            Some("alice:aws-esdk-rust-recipient-key:1".to_owned())
        );
        assert_eq!(adapter_config.local_private_key_pem, Some(private_key_pem));

        let debug = format!("{adapter_config:?}");
        assert!(debug.contains("<redacted:"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));
        assert!(!debug.contains("runtime local key"));
    }

    #[test]
    fn runtime_rejects_bad_config_keystore_unlock_material() {
        let mut config = trustless_proxy_config();
        config.local_private_key_unlock_key = [13u8; 32];

        let good_config = trustless_proxy_config();
        let private_key_pem =
            b"-----BEGIN PRIVATE KEY-----\nruntime local key\n-----END PRIVATE KEY-----\n".to_vec();

        let encrypted_private_key_blob = good_config
            .local_private_key_unlocker()
            .seal_private_key_for_storage(
                &local_private_key_selection(b"placeholder".to_vec()),
                &private_key_pem,
            )
            .unwrap();

        let err =
            LocalTrustlessRuntime::build_aws_esdk_raw_rsa_adapter_config_from_local_selection(
                &config,
                local_private_key_selection(encrypted_private_key_blob),
            )
            .unwrap_err();

        assert!(matches!(err, LocalTrustlessRuntimeError::Keyring(_)));
    }

    #[derive(Debug, Default)]
    struct RealEsdkRuntimeMockRecipientKeyResolver {
        records: std::collections::BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl RealEsdkRuntimeMockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for RealEsdkRuntimeMockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct RealEsdkRuntimeMockLocalKeystoreResolver {
        records: std::collections::BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl RealEsdkRuntimeMockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for RealEsdkRuntimeMockLocalKeystoreResolver {
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
    struct RealEsdkRuntimeMockManifestCipher;

    impl TrustlessManifestCipher for RealEsdkRuntimeMockManifestCipher {
        fn decrypt_manifest(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            if ciphertext != b"runtime-encrypted-manifest" {
                return Err(TrustlessManifestError::Cipher(
                    "unexpected runtime encrypted manifest".to_owned(),
                ));
            }

            Ok(real_esdk_runtime_manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "runtime-encrypted-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    #[derive(Debug, Clone)]
    struct RealEsdkRuntimeMockRemoteGatewayClient {
        response: CiphertextGatewayResponse,
        seen_request: std::rc::Rc<std::cell::RefCell<Option<CiphertextGatewayRequest>>>,
    }

    impl TrustlessRemoteGatewayClient for RealEsdkRuntimeMockRemoteGatewayClient {
        fn execute_ciphertext_request(
            &self,
            request: CiphertextGatewayRequest,
        ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
            *self.seen_request.borrow_mut() = Some(request);
            Ok(self.response.clone())
        }
    }

    fn real_esdk_runtime_run_openssl(args: &[&str], cwd: &std::path::Path) {
        let output = std::process::Command::new("openssl")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("failed to invoke openssl for runtime AWS ESDK Raw RSA test keys");

        assert!(
            output.status.success(),
            "openssl {:?} failed\nstdout:\n{}\nstderr:\n{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn real_esdk_runtime_generate_test_rsa_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().expect("failed to create temp dir for RSA test keys");
        let private_key = dir.path().join("private.pem");
        let public_key = dir.path().join("public.pem");

        real_esdk_runtime_run_openssl(
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

        real_esdk_runtime_run_openssl(
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

    fn real_esdk_runtime_recipient_record(
        account: &str,
        public_key_pem: &[u8],
    ) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn real_esdk_runtime_recipient_encryption_key(
        account: &str,
        public_key_pem: &[u8],
    ) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: String::from_utf8(public_key_pem.to_vec())
                .expect("test public key PEM must be UTF-8"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn real_esdk_runtime_local_record(
        config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
    ) -> LocalKeystoreRecord {
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

    fn real_esdk_runtime_preflight_builder(
        config: &TrustlessProxyConfig,
        private_key_pem: &[u8],
        public_key_pem: &[u8],
    ) -> TrustlessOperationPreflightBuilder<
        RealEsdkRuntimeMockRecipientKeyResolver,
        RealEsdkRuntimeMockLocalKeystoreResolver,
    > {
        TrustlessOperationPreflightBuilder::new(
            RealEsdkRuntimeMockRecipientKeyResolver::default()
                .with_record(real_esdk_runtime_recipient_record("alice", public_key_pem))
                .with_record(real_esdk_runtime_recipient_record("bob", public_key_pem)),
            RealEsdkRuntimeMockLocalKeystoreResolver::default()
                .with_record(real_esdk_runtime_local_record(config, private_key_pem)),
        )
    }

    fn real_esdk_runtime_envelope_context(public_key_pem: &[u8]) -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec![
                real_esdk_runtime_recipient_encryption_key("alice", public_key_pem),
                real_esdk_runtime_recipient_encryption_key("bob", public_key_pem),
            ],
        }
    }

    fn real_esdk_runtime_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: Vec::new(),
        }
    }

    fn real_esdk_runtime_manifest_entry() -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: "secret.txt".to_owned(),
            object_key_id: hex::encode([2u8; 32]),
            ciphertext_ref: "bee://runtime-ciphertext-ref".to_owned(),
            ciphertext_size: 64,
            content_type: Some("text/plain".to_owned()),
            etag: Some("runtime-etag".to_owned()),
        }
    }

    #[test]
    fn runtime_executes_put_with_configured_aws_esdk_keyring_and_ciphertext_only_remote() {
        let (private_key_pem, public_key_pem) = real_esdk_runtime_generate_test_rsa_pem_pair();
        let config = trustless_proxy_config();
        let preflight_builder =
            real_esdk_runtime_preflight_builder(&config, &private_key_pem, &public_key_pem);

        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"runtime real AWS ESDK plaintext".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let seen_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        let executor =
            TrustlessRemoteGatewayExecutor::new(RealEsdkRuntimeMockRemoteGatewayClient {
                response: CiphertextGatewayResponse {
                    action: RemoteGatewayAction::PutCiphertextObject,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    metadata_only: true,
                    gateway_plaintext_access: false,
                },
                seen_request: seen_request.clone(),
            });

        let response =
            LocalTrustlessRuntime::execute_prepared_put_operation_with_configured_aws_esdk(
                &prepared,
                real_esdk_runtime_manifest(),
                real_esdk_runtime_manifest_entry(),
                real_esdk_runtime_envelope_context(&public_key_pem),
                &config,
                &preflight_builder,
                RealEsdkRuntimeMockManifestCipher,
                &executor,
            )
            .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!response.gateway_plaintext_access);

        let request = seen_request.borrow().clone().unwrap();
        assert_eq!(request.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(!request.plaintext_payload_present);
        assert!(request.encrypted_manifest_payload.is_none());

        let ciphertext = request.ciphertext_payload.unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, b"runtime real AWS ESDK plaintext".to_vec());
        assert!(!String::from_utf8_lossy(&ciphertext).contains("runtime real AWS ESDK plaintext"));
    }

    #[test]
    fn runtime_completes_get_with_configured_aws_esdk_keyring_and_local_plaintext_only() {
        let (private_key_pem, public_key_pem) = real_esdk_runtime_generate_test_rsa_pem_pair();
        let config = trustless_proxy_config();
        let preflight_builder =
            real_esdk_runtime_preflight_builder(&config, &private_key_pem, &public_key_pem);

        let selection = local_private_key_selection(
            config
                .local_private_key_unlocker()
                .seal_private_key_for_storage(
                    &local_private_key_selection(b"placeholder".to_vec()),
                    &private_key_pem,
                )
                .unwrap(),
        );

        let keyring = LocalTrustlessRuntime::build_aws_esdk_raw_rsa_keyring_from_local_selection(
            &config, selection,
        )
        .unwrap();

        let envelope_context = real_esdk_runtime_envelope_context(&public_key_pem);
        let plaintext = b"runtime configured GET plaintext stays local".to_vec();

        let ciphertext = keyring
            .encrypt_with_recipient_envelopes(&plaintext, &envelope_context)
            .unwrap();

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let completion =
            LocalTrustlessRuntime::complete_prepared_get_response_with_configured_aws_esdk(
                prepared,
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(ciphertext),
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context,
                &config,
                &preflight_builder,
                RealEsdkRuntimeMockManifestCipher,
            )
            .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
        assert_eq!(completion.response_envelope.body, Some(plaintext));
        assert!(completion.response_envelope.plaintext_returned_locally);
        assert!(!completion.gateway_plaintext_access);
    }

    #[test]
    fn runtime_executes_delete_with_configured_aws_esdk_keyring_boundary() {
        let (private_key_pem, public_key_pem) = real_esdk_runtime_generate_test_rsa_pem_pair();
        let config = trustless_proxy_config();
        let preflight_builder =
            real_esdk_runtime_preflight_builder(&config, &private_key_pem, &public_key_pem);

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let seen_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        let executor =
            TrustlessRemoteGatewayExecutor::new(RealEsdkRuntimeMockRemoteGatewayClient {
                response: CiphertextGatewayResponse {
                    action: RemoteGatewayAction::DeleteCiphertextObject,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    metadata_only: true,
                    gateway_plaintext_access: false,
                },
                seen_request: seen_request.clone(),
            });

        let response =
            LocalTrustlessRuntime::execute_prepared_delete_operation_with_configured_aws_esdk(
                &prepared,
                TrustlessManifest {
                    entries: vec![real_esdk_runtime_manifest_entry()],
                    ..real_esdk_runtime_manifest()
                },
                real_esdk_runtime_envelope_context(&public_key_pem),
                &config,
                &preflight_builder,
                RealEsdkRuntimeMockManifestCipher,
                &executor,
            )
            .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert!(!response.gateway_plaintext_access);

        let request = seen_request.borrow().clone().unwrap();
        assert_eq!(request.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert!(request.ciphertext_payload.is_none());
        assert!(!request.plaintext_payload_present);

        let encrypted_manifest = request.encrypted_manifest_payload.unwrap();
        assert!(!encrypted_manifest.is_empty());
        assert!(
            !String::from_utf8_lossy(&encrypted_manifest)
                .contains("runtime configured GET plaintext stays local")
        );
    }

    #[test]
    fn runtime_builds_remote_http_client_from_config_and_rejects_invalid_gateway_url() {
        use std::path::PathBuf;

        use crate::config::TrustlessProxyConfig;
        use crate::gateway_boundary::CiphertextGatewayRequest;
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::RemoteGatewayClientError;

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let err = LocalTrustlessRuntime::execute_prepared_remote_http_request(
            &prepared,
            CiphertextGatewayRequest {
                bucket: "bucket".to_owned(),
                key: Some("secret.txt".to_owned()),
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                plaintext_payload_present: false,
            },
            &TrustlessProxyConfig {
                listen_host: "127.0.0.1".to_owned(),
                listen_port: 9090,
                remote_gateway_url: "not-a-url".to_owned(),
                chain_rpc_url: "ws://127.0.0.1:9944".to_owned(),
                local_account: "alice".to_owned(),
                keystore_path: PathBuf::from("./keystore.json"),
                local_private_key_unlock_key: [9u8; 32],
                aws_esdk_key_namespace: "swarm-s3-trustless-recipient".to_owned(),
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LocalTrustlessRuntimeError::RemoteGateway(RemoteGatewayClientError::Http(_))
        ));
    }
    #[test]
    fn runtime_builds_get_head_and_list_remote_requests_from_prepared_response() {
        use crate::planner::RemoteGatewayAction;

        let get_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let get_request = LocalTrustlessRuntime::build_prepared_remote_request(
            &get_prepared,
            LocalTrustlessRuntimeRemotePayload::None,
        )
        .unwrap();

        assert_eq!(get_request.bucket, "bucket");
        assert_eq!(get_request.key, Some("secret.txt".to_owned()));
        assert_eq!(get_request.action, RemoteGatewayAction::GetCiphertextObject);
        assert!(get_request.ciphertext_payload.is_none());
        assert!(get_request.encrypted_manifest_payload.is_none());
        assert!(!get_request.plaintext_payload_present);

        let head_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::HeadObject))
                .unwrap();

        let head_request = LocalTrustlessRuntime::build_prepared_remote_request(
            &head_prepared,
            LocalTrustlessRuntimeRemotePayload::None,
        )
        .unwrap();

        assert_eq!(head_request.bucket, "bucket");
        assert_eq!(head_request.key, Some("secret.txt".to_owned()));
        assert_eq!(
            head_request.action,
            RemoteGatewayAction::HeadCiphertextObject
        );
        assert!(head_request.ciphertext_payload.is_none());
        assert!(head_request.encrypted_manifest_payload.is_none());
        assert!(!head_request.plaintext_payload_present);

        let list_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            operation: LocalS3Operation::ListObjectsV2,
            key: None,
            prefix: Some("docs/".to_owned()),
            object_key_id: None,
            ..request_input(LocalS3Operation::ListObjectsV2)
        })
        .unwrap();

        let list_request = LocalTrustlessRuntime::build_prepared_remote_request(
            &list_prepared,
            LocalTrustlessRuntimeRemotePayload::None,
        )
        .unwrap();

        assert_eq!(list_request.bucket, "bucket");
        assert!(list_request.key.is_none());
        assert_eq!(
            list_request.action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert!(list_request.ciphertext_payload.is_none());
        assert!(list_request.encrypted_manifest_payload.is_none());
        assert!(!list_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_builds_put_and_delete_remote_requests_from_ciphertext_only_payloads() {
        use crate::planner::RemoteGatewayAction;

        let put_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let put_request = LocalTrustlessRuntime::build_prepared_remote_request(
            &put_prepared,
            LocalTrustlessRuntimeRemotePayload::PutCiphertext(b"ciphertext".to_vec()),
        )
        .unwrap();

        assert_eq!(put_request.bucket, "bucket");
        assert_eq!(put_request.key, Some("secret.txt".to_owned()));
        assert_eq!(put_request.action, RemoteGatewayAction::PutCiphertextObject);
        assert_eq!(put_request.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(put_request.encrypted_manifest_payload.is_none());
        assert!(!put_request.plaintext_payload_present);

        let delete_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let delete_request = LocalTrustlessRuntime::build_prepared_remote_request(
            &delete_prepared,
            LocalTrustlessRuntimeRemotePayload::DeleteEncryptedManifest(
                b"encrypted-manifest".to_vec(),
            ),
        )
        .unwrap();

        assert_eq!(delete_request.bucket, "bucket");
        assert_eq!(delete_request.key, Some("secret.txt".to_owned()));
        assert_eq!(
            delete_request.action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(delete_request.ciphertext_payload.is_none());
        assert_eq!(
            delete_request.encrypted_manifest_payload,
            Some(b"encrypted-manifest".to_vec())
        );
        assert!(!delete_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_executes_assembled_remote_request_before_executor_call() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            response: CiphertextGatewayResponse,
            seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                *self.seen_request.borrow_mut() = Some(request);
                Ok(self.response.clone())
            }
        }

        let prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let seen_request = Rc::new(RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::GetCiphertextObject,
                ciphertext_payload: Some(b"ciphertext".to_vec()),
                encrypted_manifest_payload: None,
                metadata_only: false,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let response = LocalTrustlessRuntime::execute_assembled_prepared_remote_request(
            &prepared,
            LocalTrustlessRuntimeRemotePayload::None,
            &executor,
        )
        .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(response.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(!response.gateway_plaintext_access);

        let seen_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            seen_request.action,
            RemoteGatewayAction::GetCiphertextObject
        );
        assert_eq!(seen_request.bucket, "bucket");
        assert_eq!(seen_request.key, Some("secret.txt".to_owned()));
        assert!(!seen_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_rejects_missing_or_unexpected_remote_payloads_before_execution() {
        let put_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(
            LocalTrustlessRuntime::build_prepared_remote_request(
                &put_prepared,
                LocalTrustlessRuntimeRemotePayload::None,
            )
            .unwrap_err(),
            LocalTrustlessRuntimeError::MissingPutCiphertextPayload
        );

        let get_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        assert_eq!(
            LocalTrustlessRuntime::build_prepared_remote_request(
                &get_prepared,
                LocalTrustlessRuntimeRemotePayload::PutCiphertext(b"ciphertext".to_vec()),
            )
            .unwrap_err(),
            LocalTrustlessRuntimeError::UnexpectedRemotePayloadForOperation {
                operation: LocalS3Operation::GetObject
            }
        );

        let delete_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        assert_eq!(
            LocalTrustlessRuntime::build_prepared_remote_request(
                &delete_prepared,
                LocalTrustlessRuntimeRemotePayload::None,
            )
            .unwrap_err(),
            LocalTrustlessRuntimeError::MissingDeleteEncryptedManifestPayload
        );
    }
    #[test]
    fn runtime_builds_put_and_delete_remote_requests_from_operation_plans() {
        use crate::gateway_boundary::CiphertextGatewayRequest;
        use crate::manifest::EncryptedTrustlessManifest;
        use crate::operations::{TrustlessDeleteOperationPlan, TrustlessPutOperationPlan};
        use crate::planner::RemoteGatewayAction;

        fn envelope_context() -> RecipientEnvelopeContext {
            RecipientEnvelopeContext {
                bucket_id: hex::encode([1u8; 32]),
                object_key_id: hex::encode([2u8; 32]),
                policy_version: 1,
                recipients: Vec::new(),
            }
        }

        fn encrypted_manifest(ciphertext: &[u8]) -> EncryptedTrustlessManifest {
            EncryptedTrustlessManifest {
                ciphertext: ciphertext.to_vec(),
                envelope_context: envelope_context(),
                gateway_plaintext_access: false,
            }
        }

        let put_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let put_request = LocalTrustlessRuntime::build_prepared_put_operation_remote_request(
            &put_prepared,
            TrustlessPutOperationPlan {
                object_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::PutCiphertextObject,
                    ciphertext_payload: Some(b"real-ciphertext".to_vec()),
                    encrypted_manifest_payload: None,
                    plaintext_payload_present: false,
                },
                encrypted_manifest: encrypted_manifest(b"encrypted-manifest-after-put"),
                remote_payloads_are_ciphertext_only: true,
                gateway_plaintext_access: false,
            },
        )
        .unwrap();

        assert_eq!(put_request.action, RemoteGatewayAction::PutCiphertextObject);
        assert_eq!(
            put_request.ciphertext_payload,
            Some(b"real-ciphertext".to_vec())
        );
        assert!(put_request.encrypted_manifest_payload.is_none());
        assert!(!put_request.plaintext_payload_present);

        let delete_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let delete_request = LocalTrustlessRuntime::build_prepared_delete_operation_remote_request(
            &delete_prepared,
            TrustlessDeleteOperationPlan {
                delete_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::DeleteCiphertextObject,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: Some(b"real-encrypted-manifest".to_vec()),
                    plaintext_payload_present: false,
                },
                encrypted_manifest: encrypted_manifest(b"real-encrypted-manifest"),
                remote_payloads_are_ciphertext_only: true,
                gateway_plaintext_access: false,
            },
        )
        .unwrap();

        assert_eq!(
            delete_request.action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(delete_request.ciphertext_payload.is_none());
        assert_eq!(
            delete_request.encrypted_manifest_payload,
            Some(b"real-encrypted-manifest".to_vec())
        );
        assert!(!delete_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_executes_put_operation_plan_through_remote_executor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::manifest::EncryptedTrustlessManifest;
        use crate::operations::TrustlessPutOperationPlan;
        use crate::planner::RemoteGatewayAction;
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            response: CiphertextGatewayResponse,
            seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                *self.seen_request.borrow_mut() = Some(request);
                Ok(self.response.clone())
            }
        }

        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let seen_request = Rc::new(RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let response = LocalTrustlessRuntime::execute_prepared_put_operation_remote_request(
            &prepared,
            TrustlessPutOperationPlan {
                object_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::PutCiphertextObject,
                    ciphertext_payload: Some(b"real-ciphertext".to_vec()),
                    encrypted_manifest_payload: None,
                    plaintext_payload_present: false,
                },
                encrypted_manifest: EncryptedTrustlessManifest {
                    ciphertext: b"encrypted-manifest-after-put".to_vec(),
                    envelope_context: RecipientEnvelopeContext {
                        bucket_id: hex::encode([1u8; 32]),
                        object_key_id: hex::encode([2u8; 32]),
                        policy_version: 1,
                        recipients: Vec::new(),
                    },
                    gateway_plaintext_access: false,
                },
                remote_payloads_are_ciphertext_only: true,
                gateway_plaintext_access: false,
            },
            &executor,
        )
        .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(response.metadata_only);
        assert!(!response.gateway_plaintext_access);

        let seen_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            seen_request.action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert_eq!(
            seen_request.ciphertext_payload,
            Some(b"real-ciphertext".to_vec())
        );
        assert!(seen_request.encrypted_manifest_payload.is_none());
        assert!(!seen_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_rejects_invalid_operation_plan_remote_boundaries() {
        use crate::gateway_boundary::CiphertextGatewayRequest;
        use crate::manifest::EncryptedTrustlessManifest;
        use crate::operations::{TrustlessDeleteOperationPlan, TrustlessPutOperationPlan};
        use crate::planner::RemoteGatewayAction;

        fn envelope_context() -> RecipientEnvelopeContext {
            RecipientEnvelopeContext {
                bucket_id: hex::encode([1u8; 32]),
                object_key_id: hex::encode([2u8; 32]),
                policy_version: 1,
                recipients: Vec::new(),
            }
        }

        fn encrypted_manifest(gateway_plaintext_access: bool) -> EncryptedTrustlessManifest {
            EncryptedTrustlessManifest {
                ciphertext: b"encrypted-manifest".to_vec(),
                envelope_context: envelope_context(),
                gateway_plaintext_access,
            }
        }

        let put_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let err = LocalTrustlessRuntime::build_prepared_put_operation_remote_request(
            &put_prepared,
            TrustlessPutOperationPlan {
                object_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::DeleteCiphertextObject,
                    ciphertext_payload: Some(b"real-ciphertext".to_vec()),
                    encrypted_manifest_payload: None,
                    plaintext_payload_present: false,
                },
                encrypted_manifest: encrypted_manifest(false),
                remote_payloads_are_ciphertext_only: true,
                gateway_plaintext_access: false,
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::OperationPlanRemoteActionMismatch {
                expected: RemoteGatewayAction::PutCiphertextObject,
                actual: RemoteGatewayAction::DeleteCiphertextObject,
            }
        );

        let err = LocalTrustlessRuntime::build_prepared_put_operation_remote_request(
            &put_prepared,
            TrustlessPutOperationPlan {
                object_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::PutCiphertextObject,
                    ciphertext_payload: Some(b"real-ciphertext".to_vec()),
                    encrypted_manifest_payload: None,
                    plaintext_payload_present: false,
                },
                encrypted_manifest: encrypted_manifest(false),
                remote_payloads_are_ciphertext_only: false,
                gateway_plaintext_access: false,
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::OperationPlanAllowsNonCiphertextRemotePayload
        );

        let delete_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let err = LocalTrustlessRuntime::build_prepared_delete_operation_remote_request(
            &delete_prepared,
            TrustlessDeleteOperationPlan {
                delete_request: CiphertextGatewayRequest {
                    bucket: "bucket".to_owned(),
                    key: Some("secret.txt".to_owned()),
                    action: RemoteGatewayAction::DeleteCiphertextObject,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: Some(b"encrypted-manifest".to_vec()),
                    plaintext_payload_present: false,
                },
                encrypted_manifest: encrypted_manifest(true),
                remote_payloads_are_ciphertext_only: true,
                gateway_plaintext_access: false,
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::GatewayPlaintextAccessRejected
        );
    }
    use std::collections::BTreeMap;

    use crate::local_keystore::LocalKeystoreResolver;
    use crate::manifest::{TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry};
    use crate::operations::TrustlessOperationAssembler;
    use crate::recipient_keys::RecipientKeyResolver;

    #[derive(Debug, Default)]
    struct RuntimeMockRecipientKeyResolver {
        records: BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl RuntimeMockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for RuntimeMockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct RuntimeMockLocalKeystoreResolver {
        records: BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl RuntimeMockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for RuntimeMockLocalKeystoreResolver {
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
    struct RuntimeMockKeyring;

    impl crate::keyring::TrustlessRecipientKeyring for RuntimeMockKeyring {
        fn keyring_name(&self) -> &'static str {
            "runtime-mock-keyring"
        }

        fn encrypt_with_recipient_envelopes(
            &self,
            plaintext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, crate::keyring::KeyringError> {
            let mut ciphertext = b"ciphertext:".to_vec();
            ciphertext.extend_from_slice(plaintext);
            Ok(ciphertext)
        }

        fn decrypt_with_local_recipient_key(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, crate::keyring::KeyringError> {
            let prefix = b"ciphertext:";
            ciphertext
                .strip_prefix(prefix)
                .map(Vec::from)
                .ok_or(crate::keyring::KeyringError::DecryptNotImplemented)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct RuntimeMockManifestCipher;

    impl TrustlessManifestCipher for RuntimeMockManifestCipher {
        fn decrypt_manifest(
            &self,
            _ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            Ok(runtime_manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "encrypted-runtime-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    fn runtime_recipient_record(account: &str) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: format!("{account}-public-key"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn runtime_local_record(version: u32) -> LocalKeystoreRecord {
        LocalKeystoreRecord {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: version,
            encrypted_private_key_blob: vec![1, 2, 3, version as u8],
            enabled: true,
            storage_label: format!("local-keystore/alice/{version}"),
        }
    }

    fn runtime_preflight_builder() -> TrustlessOperationPreflightBuilder<
        RuntimeMockRecipientKeyResolver,
        RuntimeMockLocalKeystoreResolver,
    > {
        TrustlessOperationPreflightBuilder::new(
            RuntimeMockRecipientKeyResolver::default()
                .with_record(runtime_recipient_record("alice"))
                .with_record(runtime_recipient_record("bob")),
            RuntimeMockLocalKeystoreResolver::default().with_record(runtime_local_record(7)),
        )
    }

    fn runtime_assembler()
    -> TrustlessOperationAssembler<RuntimeMockKeyring, RuntimeMockManifestCipher> {
        TrustlessOperationAssembler::new(RuntimeMockKeyring, RuntimeMockManifestCipher)
    }

    fn runtime_manifest_entry(object_key: &str, object_key_id: &str) -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: object_key.to_owned(),
            object_key_id: object_key_id.to_owned(),
            ciphertext_ref: format!("swarm://ciphertext/{object_key_id}"),
            ciphertext_size: 128,
            content_type: Some("text/plain".to_owned()),
            etag: Some(format!("etag-{object_key_id}")),
        }
    }

    fn runtime_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: vec![runtime_manifest_entry(
                "secret.txt",
                &hex::encode([2u8; 32]),
            )],
        }
    }

    fn runtime_empty_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: Vec::new(),
        }
    }

    fn runtime_envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
        }
    }

    #[test]
    fn runtime_builds_put_and_delete_operation_plans_from_prepared_state() {
        let put_prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let put_plan = LocalTrustlessRuntime::build_prepared_put_operation_plan(
            &put_prepared,
            runtime_empty_manifest(),
            runtime_manifest_entry("secret.txt", &hex::encode([2u8; 32])),
            runtime_envelope_context(),
            &runtime_preflight_builder(),
            &runtime_assembler(),
        )
        .unwrap();

        assert_eq!(
            put_plan.object_request.action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert_eq!(
            put_plan.object_request.ciphertext_payload,
            Some(b"ciphertext:secret".to_vec())
        );
        assert!(put_plan.remote_payloads_are_ciphertext_only);
        assert!(!put_plan.gateway_plaintext_access);
        assert!(!put_plan.encrypted_manifest.ciphertext.is_empty());

        let delete_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let delete_plan = LocalTrustlessRuntime::build_prepared_delete_operation_plan(
            &delete_prepared,
            runtime_manifest(),
            runtime_envelope_context(),
            &runtime_preflight_builder(),
            &runtime_assembler(),
        )
        .unwrap();

        assert_eq!(
            delete_plan.delete_request.action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(delete_plan.delete_request.ciphertext_payload.is_none());
        assert!(
            delete_plan
                .delete_request
                .encrypted_manifest_payload
                .is_some()
        );
        assert!(delete_plan.remote_payloads_are_ciphertext_only);
        assert!(!delete_plan.gateway_plaintext_access);
    }

    #[test]
    fn runtime_executes_put_operation_from_prepared_state_through_executor() {
        use std::cell::RefCell;
        use std::rc::Rc;

        use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
        use crate::remote_gateway::{
            RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
        };

        #[derive(Debug, Clone)]
        struct MockRemoteGatewayClient {
            response: CiphertextGatewayResponse,
            seen_request: Rc<RefCell<Option<CiphertextGatewayRequest>>>,
        }

        impl TrustlessRemoteGatewayClient for MockRemoteGatewayClient {
            fn execute_ciphertext_request(
                &self,
                request: CiphertextGatewayRequest,
            ) -> Result<CiphertextGatewayResponse, RemoteGatewayClientError> {
                *self.seen_request.borrow_mut() = Some(request);
                Ok(self.response.clone())
            }
        }

        let prepared = LocalTrustlessRuntime::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let seen_request = Rc::new(RefCell::new(None));
        let executor = TrustlessRemoteGatewayExecutor::new(MockRemoteGatewayClient {
            response: CiphertextGatewayResponse {
                action: RemoteGatewayAction::PutCiphertextObject,
                ciphertext_payload: None,
                encrypted_manifest_payload: None,
                metadata_only: true,
                gateway_plaintext_access: false,
            },
            seen_request: seen_request.clone(),
        });

        let response = LocalTrustlessRuntime::execute_prepared_put_operation(
            &prepared,
            runtime_empty_manifest(),
            runtime_manifest_entry("secret.txt", &hex::encode([2u8; 32])),
            runtime_envelope_context(),
            &runtime_preflight_builder(),
            &runtime_assembler(),
            &executor,
        )
        .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::PutCiphertextObject);
        assert!(response.metadata_only);
        assert!(!response.gateway_plaintext_access);

        let seen_request = seen_request.borrow().clone().unwrap();
        assert_eq!(
            seen_request.action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert_eq!(
            seen_request.ciphertext_payload,
            Some(b"ciphertext:secret".to_vec())
        );
        assert!(!seen_request.plaintext_payload_present);
    }

    #[test]
    fn runtime_rejects_wrong_prepared_operation_for_end_to_end_orchestration() {
        let get_prepared =
            LocalTrustlessRuntime::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let err = LocalTrustlessRuntime::build_prepared_put_operation_plan(
            &get_prepared,
            runtime_empty_manifest(),
            runtime_manifest_entry("secret.txt", &hex::encode([2u8; 32])),
            runtime_envelope_context(),
            &runtime_preflight_builder(),
            &runtime_assembler(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessRuntimeError::UnexpectedPreparedOperation {
                expected: LocalS3Operation::PutObject,
                actual: LocalS3Operation::GetObject,
            }
        );
    }
}
