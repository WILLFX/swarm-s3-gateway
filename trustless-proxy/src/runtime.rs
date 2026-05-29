use thiserror::Error;

use crate::config::TrustlessProxyConfig;
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
use crate::planner::{PlannerError, TrustlessRoutePlanner};
use crate::preflight::TrustlessPreflightRequest;
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

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("prepared runtime response does not require remote gateway execution")]
    PreparedResponseDoesNotRequireRemoteGateway,

    #[error("prepared PUT remote request requires ciphertext payload")]
    MissingPutCiphertextPayload,

    #[error("prepared DELETE remote request requires encrypted manifest payload")]
    MissingDeleteEncryptedManifestPayload,

    #[error("prepared remote request payload is not valid for operation {operation:?}")]
    UnexpectedRemotePayloadForOperation { operation: LocalS3Operation },

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
    use crate::request_adapter::LocalTrustlessRequestInput;
    use crate::response_adapter::LocalTrustlessResponseState;
    use crate::service::TrustlessLocalServiceNextAction;

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
}
