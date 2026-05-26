use thiserror::Error;

use crate::execution_coordinator::TrustlessExecutionResult;
use crate::request_adapter::{
    LocalTrustlessRequestAdapter, LocalTrustlessRequestAdapterError, LocalTrustlessRequestInput,
    LocalTrustlessRequestPreparation,
};
use crate::response_adapter::{
    LocalTrustlessResponseAdapter, LocalTrustlessResponseAdapterError,
    LocalTrustlessResponseEnvelope,
};
use crate::s3_surface::LocalS3Operation;
use crate::service::{
    TrustlessLocalService, TrustlessLocalServiceError, TrustlessLocalServicePreparedOperation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHandlerPreparedResponse {
    pub operation: LocalS3Operation,
    pub request_preparation: LocalTrustlessRequestPreparation,
    pub response_envelope: LocalTrustlessResponseEnvelope,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessHandlerCompletion {
    pub operation: LocalS3Operation,
    pub execution_result: TrustlessExecutionResult,
    pub response_envelope: LocalTrustlessResponseEnvelope,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessHandlerError {
    #[error(transparent)]
    RequestAdapter(LocalTrustlessRequestAdapterError),

    #[error(transparent)]
    ResponseAdapter(LocalTrustlessResponseAdapterError),

    #[error(transparent)]
    Service(TrustlessLocalServiceError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

impl From<LocalTrustlessRequestAdapterError> for LocalTrustlessHandlerError {
    fn from(error: LocalTrustlessRequestAdapterError) -> Self {
        Self::RequestAdapter(error)
    }
}

impl From<LocalTrustlessResponseAdapterError> for LocalTrustlessHandlerError {
    fn from(error: LocalTrustlessResponseAdapterError) -> Self {
        Self::ResponseAdapter(error)
    }
}

impl From<TrustlessLocalServiceError> for LocalTrustlessHandlerError {
    fn from(error: TrustlessLocalServiceError) -> Self {
        Self::Service(error)
    }
}

pub struct LocalTrustlessHandler;

impl LocalTrustlessHandler {
    pub fn prepare_request(
        input: LocalTrustlessRequestInput,
    ) -> Result<LocalTrustlessHandlerPreparedResponse, LocalTrustlessHandlerError> {
        let request_preparation = LocalTrustlessRequestAdapter::prepare(input)?;

        if request_preparation.gateway_plaintext_access
            || request_preparation
                .prepared_operation
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessHandlerError::GatewayPlaintextAccessRejected);
        }

        let operation = request_preparation.prepared_operation.operation;
        let response_envelope = LocalTrustlessResponseAdapter::from_prepared_operation(
            request_preparation.prepared_operation.clone(),
        )?;

        if response_envelope.gateway_plaintext_access {
            return Err(LocalTrustlessHandlerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessHandlerPreparedResponse {
            operation,
            request_preparation,
            response_envelope,
            gateway_plaintext_access: false,
        })
    }

    pub fn complete_get_with_plaintext(
        prepared_operation: TrustlessLocalServicePreparedOperation,
        plaintext: Vec<u8>,
    ) -> Result<LocalTrustlessHandlerCompletion, LocalTrustlessHandlerError> {
        let execution_result =
            TrustlessLocalService::complete_get_with_plaintext(prepared_operation, plaintext)?;

        if execution_result.gateway_plaintext_access {
            return Err(LocalTrustlessHandlerError::GatewayPlaintextAccessRejected);
        }

        let operation = execution_result.operation;
        let response_envelope =
            LocalTrustlessResponseAdapter::from_execution_result(execution_result.clone())?;

        if response_envelope.gateway_plaintext_access {
            return Err(LocalTrustlessHandlerError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessHandlerCompletion {
            operation,
            execution_result,
            response_envelope,
            gateway_plaintext_access: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn handler_prepares_put_as_pending_ciphertext_remote_response() {
        let prepared = LocalTrustlessHandler::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::PutObject);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(prepared.response_envelope.status_code, 202);
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(prepared.response_envelope.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn handler_prepares_get_as_pending_local_decrypt_response() {
        let prepared =
            LocalTrustlessHandler::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::GetObject);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingLocalDecrypt
        );
        assert_eq!(prepared.response_envelope.status_code, 202);
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally)
        );
        assert!(prepared.response_envelope.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn handler_completes_get_as_local_plaintext_response() {
        let prepared =
            LocalTrustlessHandler::prepare_request(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let completion = LocalTrustlessHandler::complete_get_with_plaintext(
            prepared.request_preparation.prepared_operation,
            b"secret".to_vec(),
        )
        .unwrap();

        assert_eq!(completion.operation, LocalS3Operation::GetObject);
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
    fn handler_prepares_delete_as_pending_ciphertext_remote_response() {
        let prepared =
            LocalTrustlessHandler::prepare_request(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::DeleteObject);
        assert_eq!(
            prepared.response_envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(
            prepared.response_envelope.next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(prepared.response_envelope.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn handler_prepares_create_bucket_as_pending_anchor_response() {
        let prepared = LocalTrustlessHandler::prepare_request(LocalTrustlessRequestInput {
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
        assert!(!prepared.response_envelope.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn handler_prepares_list_without_object_key_id() {
        let prepared = LocalTrustlessHandler::prepare_request(LocalTrustlessRequestInput {
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
        assert!(prepared.response_envelope.remote_gateway_required);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn handler_rejects_plaintext_body_outside_put_boundary() {
        let err = LocalTrustlessHandler::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"bad".to_vec()),
            ..request_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessHandlerError::RequestAdapter(_)));
    }

    #[test]
    fn handler_rejects_completing_non_get_as_plaintext() {
        let prepared = LocalTrustlessHandler::prepare_request(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let err = LocalTrustlessHandler::complete_get_with_plaintext(
            prepared.request_preparation.prepared_operation,
            b"secret".to_vec(),
        )
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessHandlerError::Service(_)));
    }
}
