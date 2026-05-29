use thiserror::Error;

use crate::config::TrustlessProxyConfig;
use crate::execution_coordinator::{
    TrustlessExecutionCoordinator, TrustlessExecutionCoordinatorError,
};
use crate::gateway_boundary::{CiphertextGatewayRequest, CiphertextGatewayResponse};
use crate::handler::{
    LocalTrustlessHandler, LocalTrustlessHandlerCompletion, LocalTrustlessHandlerError,
    LocalTrustlessHandlerPreparedResponse,
};
use crate::remote_gateway::{
    RemoteGatewayClientError, TrustlessRemoteGatewayClient, TrustlessRemoteGatewayExecutor,
};
use crate::remote_gateway_http::RemoteGatewayHttpClient;
use crate::request_adapter::LocalTrustlessRequestInput;
use crate::response_adapter::{LocalTrustlessResponseEnvelope, LocalTrustlessResponseState};
use crate::s3_surface::LocalS3Operation;

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessRuntimeError {
    #[error(transparent)]
    Handler(LocalTrustlessHandlerError),

    #[error(transparent)]
    RemoteGateway(RemoteGatewayClientError),

    #[error(transparent)]
    ExecutionCoordinator(TrustlessExecutionCoordinatorError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("prepared runtime response does not require remote gateway execution")]
    PreparedResponseDoesNotRequireRemoteGateway,

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
}
