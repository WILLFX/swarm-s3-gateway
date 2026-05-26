use thiserror::Error;

use crate::execution_coordinator::TrustlessExecutionResult;
use crate::s3_surface::{LocalS3Operation, LocalS3Response};
use crate::service::{TrustlessLocalServiceNextAction, TrustlessLocalServicePreparedOperation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTrustlessResponseState {
    PendingCiphertextOnlyRemoteRequest,
    PendingLocalDecrypt,
    PendingTrustlessBucketAnchor,
    ReadyMetadataOnly,
    ReadyLocalPlaintext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessResponseEnvelope {
    pub operation: LocalS3Operation,
    pub state: LocalTrustlessResponseState,
    pub status_code: u16,
    pub body: Option<Vec<u8>>,
    pub metadata_only: bool,
    pub plaintext_returned_locally: bool,
    pub remote_gateway_required: bool,
    pub next_action: Option<TrustlessLocalServiceNextAction>,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessResponseAdapterError {
    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("GET preparation must wait for ciphertext and local decrypt")]
    InvalidPreparedGetResponse,

    #[error("remote operation must require ciphertext-only remote gateway action")]
    MissingCiphertextRemoteAction,

    #[error("GET execution result requires a local plaintext body")]
    MissingGetPlaintextBody,

    #[error("plaintext response is only valid for GET")]
    UnexpectedPlaintextBody,

    #[error("metadata-only response is not valid for GET")]
    UnexpectedMetadataOnlyGet,

    #[error("metadata response was expected")]
    MissingMetadataResponse,
}

pub struct LocalTrustlessResponseAdapter;

impl LocalTrustlessResponseAdapter {
    pub fn from_prepared_operation(
        prepared: TrustlessLocalServicePreparedOperation,
    ) -> Result<LocalTrustlessResponseEnvelope, LocalTrustlessResponseAdapterError> {
        if prepared.gateway_plaintext_access
            || prepared.pipeline_plan.gateway_plaintext_access
            || prepared.pipeline_plan.route.gateway_plaintext_access
            || prepared
                .pipeline_plan
                .request_context
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessResponseAdapterError::GatewayPlaintextAccessRejected);
        }

        let operation = prepared.operation;
        let next_action = prepared.next_action;
        let remote_gateway_required = prepared.remote_gateway_required;
        let metadata_only = prepared
            .expected_local_response
            .as_ref()
            .map(|response| response.metadata_only)
            .unwrap_or(false);

        let state = match next_action {
            TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally => {
                if operation != LocalS3Operation::GetObject
                    || prepared.expected_local_response.is_some()
                    || !remote_gateway_required
                {
                    return Err(LocalTrustlessResponseAdapterError::InvalidPreparedGetResponse);
                }

                LocalTrustlessResponseState::PendingLocalDecrypt
            }
            TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest => {
                if !remote_gateway_required {
                    return Err(LocalTrustlessResponseAdapterError::MissingCiphertextRemoteAction);
                }

                LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
            }
            TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor => {
                if remote_gateway_required {
                    return Err(LocalTrustlessResponseAdapterError::MissingCiphertextRemoteAction);
                }

                LocalTrustlessResponseState::PendingTrustlessBucketAnchor
            }
        };

        Ok(LocalTrustlessResponseEnvelope {
            operation,
            state,
            status_code: 202,
            body: None,
            metadata_only,
            plaintext_returned_locally: false,
            remote_gateway_required,
            next_action: Some(next_action),
            gateway_plaintext_access: false,
        })
    }

    pub fn from_execution_result(
        result: TrustlessExecutionResult,
    ) -> Result<LocalTrustlessResponseEnvelope, LocalTrustlessResponseAdapterError> {
        if result.gateway_plaintext_access
            || result.pipeline_plan.gateway_plaintext_access
            || result.pipeline_plan.route.gateway_plaintext_access
            || result
                .pipeline_plan
                .request_context
                .gateway_plaintext_access
        {
            return Err(LocalTrustlessResponseAdapterError::GatewayPlaintextAccessRejected);
        }

        let operation = result.operation;
        let remote_gateway_required = result.boundary_requirements.remote_gateway_required;

        Self::from_local_response(operation, result.local_response, remote_gateway_required)
    }

    pub fn from_local_response(
        operation: LocalS3Operation,
        response: LocalS3Response,
        remote_gateway_required: bool,
    ) -> Result<LocalTrustlessResponseEnvelope, LocalTrustlessResponseAdapterError> {
        if response.gateway_plaintext_access {
            return Err(LocalTrustlessResponseAdapterError::GatewayPlaintextAccessRejected);
        }

        if response.operation != operation {
            return Err(LocalTrustlessResponseAdapterError::MissingMetadataResponse);
        }

        let metadata_only = response.metadata_only;
        let plaintext_returned_locally = response.plaintext_returned_locally;
        let body = response.plaintext_body;

        if let Some(body) = body {
            if operation != LocalS3Operation::GetObject || !plaintext_returned_locally {
                return Err(LocalTrustlessResponseAdapterError::UnexpectedPlaintextBody);
            }

            if body.is_empty() {
                return Err(LocalTrustlessResponseAdapterError::MissingGetPlaintextBody);
            }

            return Ok(LocalTrustlessResponseEnvelope {
                operation,
                state: LocalTrustlessResponseState::ReadyLocalPlaintext,
                status_code: 200,
                body: Some(body),
                metadata_only: false,
                plaintext_returned_locally: true,
                remote_gateway_required,
                next_action: None,
                gateway_plaintext_access: false,
            });
        }

        if operation == LocalS3Operation::GetObject {
            return Err(LocalTrustlessResponseAdapterError::MissingGetPlaintextBody);
        }

        if !metadata_only {
            return Err(LocalTrustlessResponseAdapterError::MissingMetadataResponse);
        }

        Ok(LocalTrustlessResponseEnvelope {
            operation,
            state: LocalTrustlessResponseState::ReadyMetadataOnly,
            status_code: metadata_status_code(operation),
            body: None,
            metadata_only: true,
            plaintext_returned_locally: false,
            remote_gateway_required,
            next_action: None,
            gateway_plaintext_access: false,
        })
    }
}

fn metadata_status_code(operation: LocalS3Operation) -> u16 {
    match operation {
        LocalS3Operation::DeleteObject => 204,
        LocalS3Operation::PutObject
        | LocalS3Operation::HeadObject
        | LocalS3Operation::ListObjectsV2
        | LocalS3Operation::CreateTrustlessBucket => 200,
        LocalS3Operation::GetObject => 500,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution_coordinator::TrustlessExecutionCoordinator;
    use crate::request_adapter::{LocalTrustlessRequestAdapter, LocalTrustlessRequestInput};
    use crate::service::TrustlessLocalService;

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
    fn response_adapter_marks_put_preparation_as_pending_ciphertext_remote() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let envelope =
            LocalTrustlessResponseAdapter::from_prepared_operation(preparation.prepared_operation)
                .unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::PutObject);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::PendingCiphertextOnlyRemoteRequest
        );
        assert_eq!(envelope.status_code, 202);
        assert!(envelope.body.is_none());
        assert!(envelope.remote_gateway_required);
        assert_eq!(
            envelope.next_action,
            Some(TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest)
        );
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_marks_get_preparation_as_pending_local_decrypt() {
        let preparation =
            LocalTrustlessRequestAdapter::prepare(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let envelope =
            LocalTrustlessResponseAdapter::from_prepared_operation(preparation.prepared_operation)
                .unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::GetObject);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::PendingLocalDecrypt
        );
        assert_eq!(envelope.status_code, 202);
        assert!(envelope.body.is_none());
        assert!(envelope.remote_gateway_required);
        assert_eq!(
            envelope.next_action,
            Some(TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally)
        );
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_marks_create_bucket_preparation_as_pending_anchor() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            operation: LocalS3Operation::CreateTrustlessBucket,
            key: None,
            object_key_id: None,
            ..request_input(LocalS3Operation::CreateTrustlessBucket)
        })
        .unwrap();

        let envelope =
            LocalTrustlessResponseAdapter::from_prepared_operation(preparation.prepared_operation)
                .unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::CreateTrustlessBucket);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::PendingTrustlessBucketAnchor
        );
        assert_eq!(envelope.status_code, 202);
        assert!(!envelope.remote_gateway_required);
        assert_eq!(
            envelope.next_action,
            Some(TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor)
        );
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_builds_final_get_plaintext_response() {
        let preparation =
            LocalTrustlessRequestAdapter::prepare(request_input(LocalS3Operation::GetObject))
                .unwrap();

        let result = TrustlessLocalService::complete_get_with_plaintext(
            preparation.prepared_operation,
            b"secret".to_vec(),
        )
        .unwrap();

        let envelope = LocalTrustlessResponseAdapter::from_execution_result(result).unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::GetObject);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::ReadyLocalPlaintext
        );
        assert_eq!(envelope.status_code, 200);
        assert_eq!(envelope.body, Some(b"secret".to_vec()));
        assert!(envelope.plaintext_returned_locally);
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_builds_final_metadata_response() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let result = TrustlessExecutionCoordinator::coordinate_metadata_response(
            preparation.prepared_operation.pipeline_plan,
        )
        .unwrap();

        let envelope = LocalTrustlessResponseAdapter::from_execution_result(result).unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::PutObject);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::ReadyMetadataOnly
        );
        assert_eq!(envelope.status_code, 200);
        assert!(envelope.body.is_none());
        assert!(envelope.metadata_only);
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_builds_delete_metadata_response_with_no_content_status() {
        let preparation =
            LocalTrustlessRequestAdapter::prepare(request_input(LocalS3Operation::DeleteObject))
                .unwrap();

        let result = TrustlessExecutionCoordinator::coordinate_metadata_response(
            preparation.prepared_operation.pipeline_plan,
        )
        .unwrap();

        let envelope = LocalTrustlessResponseAdapter::from_execution_result(result).unwrap();

        assert_eq!(envelope.operation, LocalS3Operation::DeleteObject);
        assert_eq!(
            envelope.state,
            LocalTrustlessResponseState::ReadyMetadataOnly
        );
        assert_eq!(envelope.status_code, 204);
        assert!(envelope.body.is_none());
        assert!(!envelope.gateway_plaintext_access);
    }

    #[test]
    fn response_adapter_rejects_gateway_plaintext_prepared_operation() {
        let mut preparation =
            LocalTrustlessRequestAdapter::prepare(request_input(LocalS3Operation::GetObject))
                .unwrap();

        preparation.prepared_operation.gateway_plaintext_access = true;

        let err =
            LocalTrustlessResponseAdapter::from_prepared_operation(preparation.prepared_operation)
                .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessResponseAdapterError::GatewayPlaintextAccessRejected
        );
    }

    #[test]
    fn response_adapter_rejects_get_execution_without_plaintext_body() {
        let response = LocalS3Response {
            operation: LocalS3Operation::GetObject,
            plaintext_body: None,
            metadata_only: true,
            plaintext_returned_locally: false,
            gateway_plaintext_access: false,
        };

        let err = LocalTrustlessResponseAdapter::from_local_response(
            LocalS3Operation::GetObject,
            response,
            true,
        )
        .unwrap_err();

        assert_eq!(
            err,
            LocalTrustlessResponseAdapterError::MissingGetPlaintextBody
        );
    }
}
