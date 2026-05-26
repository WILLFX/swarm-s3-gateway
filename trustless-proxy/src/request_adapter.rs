use thiserror::Error;

use crate::pipeline::TrustlessPipelineInput;
use crate::s3_surface::{LocalS3Operation, LocalS3Request};
use crate::service::{
    TrustlessLocalService, TrustlessLocalServiceError, TrustlessLocalServicePreparedOperation,
};
use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessRequestInput {
    pub operation: LocalS3Operation,
    pub bucket: String,
    pub key: Option<String>,
    pub prefix: Option<String>,
    pub plaintext_body: Option<Vec<u8>>,
    pub bucket_id: String,
    pub object_key_id: Option<String>,
    pub policy_version: u32,
    pub local_account: SubstrateAccountId,
    pub local_key_type: String,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTrustlessRequestPreparation {
    pub s3_request: LocalS3Request,
    pub pipeline_input: TrustlessPipelineInput,
    pub prepared_operation: TrustlessLocalServicePreparedOperation,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalTrustlessRequestAdapterError {
    #[error(transparent)]
    Service(TrustlessLocalServiceError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

impl From<TrustlessLocalServiceError> for LocalTrustlessRequestAdapterError {
    fn from(error: TrustlessLocalServiceError) -> Self {
        Self::Service(error)
    }
}

pub struct LocalTrustlessRequestAdapter;

impl LocalTrustlessRequestAdapter {
    pub fn build_s3_request(input: &LocalTrustlessRequestInput) -> LocalS3Request {
        LocalS3Request {
            operation: input.operation,
            bucket: input.bucket.clone(),
            key: input.key.clone(),
            prefix: input.prefix.clone(),
            plaintext_body: input.plaintext_body.clone(),
            plaintext_body_allowed_locally: input.operation == LocalS3Operation::PutObject
                && input.plaintext_body.is_some(),
        }
    }

    pub fn build_pipeline_input(input: LocalTrustlessRequestInput) -> TrustlessPipelineInput {
        let s3_request = Self::build_s3_request(&input);

        TrustlessPipelineInput {
            s3_request,
            bucket_id: input.bucket_id,
            object_key_id: input.object_key_id,
            policy_version: input.policy_version,
            local_account: input.local_account,
            local_key_type: input.local_key_type,
            recipients: input.recipients,
        }
    }

    pub fn prepare(
        input: LocalTrustlessRequestInput,
    ) -> Result<LocalTrustlessRequestPreparation, LocalTrustlessRequestAdapterError> {
        let s3_request = Self::build_s3_request(&input);
        let pipeline_input = Self::build_pipeline_input(input);

        let prepared_operation = TrustlessLocalService::prepare(pipeline_input.clone())?;

        if prepared_operation.gateway_plaintext_access {
            return Err(LocalTrustlessRequestAdapterError::GatewayPlaintextAccessRejected);
        }

        Ok(LocalTrustlessRequestPreparation {
            s3_request,
            pipeline_input,
            prepared_operation,
            gateway_plaintext_access: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn adapter_builds_put_pipeline_input_with_local_plaintext_only() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            plaintext_body: Some(b"secret".to_vec()),
            ..request_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(
            preparation.s3_request.operation,
            LocalS3Operation::PutObject
        );
        assert_eq!(
            preparation.s3_request.plaintext_body,
            Some(b"secret".to_vec())
        );
        assert!(preparation.s3_request.plaintext_body_allowed_locally);
        assert_eq!(
            preparation.prepared_operation.next_action,
            TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
        );
        assert!(preparation.prepared_operation.remote_gateway_required);
        assert!(!preparation.gateway_plaintext_access);
    }

    #[test]
    fn adapter_builds_get_pipeline_input_awaiting_local_decrypt() {
        let preparation =
            LocalTrustlessRequestAdapter::prepare(request_input(LocalS3Operation::GetObject))
                .unwrap();

        assert_eq!(
            preparation.s3_request.operation,
            LocalS3Operation::GetObject
        );
        assert!(preparation.s3_request.plaintext_body.is_none());
        assert!(!preparation.s3_request.plaintext_body_allowed_locally);
        assert_eq!(
            preparation.prepared_operation.next_action,
            TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally
        );
        assert!(
            preparation
                .prepared_operation
                .expected_local_response
                .is_none()
        );
        assert!(!preparation.gateway_plaintext_access);
    }

    #[test]
    fn adapter_builds_head_delete_as_ciphertext_remote_metadata_operations() {
        for operation in [LocalS3Operation::HeadObject, LocalS3Operation::DeleteObject] {
            let preparation =
                LocalTrustlessRequestAdapter::prepare(request_input(operation)).unwrap();

            assert_eq!(preparation.s3_request.operation, operation);
            assert_eq!(
                preparation.prepared_operation.next_action,
                TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
            );
            assert!(preparation.prepared_operation.remote_gateway_required);
            assert!(
                preparation
                    .prepared_operation
                    .expected_local_response
                    .unwrap()
                    .metadata_only
            );
            assert!(!preparation.gateway_plaintext_access);
        }
    }

    #[test]
    fn adapter_builds_list_pipeline_input_without_object_key_id() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            operation: LocalS3Operation::ListObjectsV2,
            key: None,
            prefix: Some("docs/".to_owned()),
            object_key_id: None,
            ..request_input(LocalS3Operation::ListObjectsV2)
        })
        .unwrap();

        assert_eq!(
            preparation.s3_request.operation,
            LocalS3Operation::ListObjectsV2
        );
        assert_eq!(preparation.s3_request.prefix, Some("docs/".to_owned()));
        assert!(preparation.pipeline_input.object_key_id.is_none());
        assert_eq!(
            preparation.prepared_operation.next_action,
            TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
        );
        assert!(!preparation.gateway_plaintext_access);
    }

    #[test]
    fn adapter_builds_create_bucket_anchor_without_remote_gateway() {
        let preparation = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            operation: LocalS3Operation::CreateTrustlessBucket,
            key: None,
            object_key_id: None,
            ..request_input(LocalS3Operation::CreateTrustlessBucket)
        })
        .unwrap();

        assert_eq!(
            preparation.s3_request.operation,
            LocalS3Operation::CreateTrustlessBucket
        );
        assert_eq!(
            preparation.prepared_operation.next_action,
            TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor
        );
        assert!(!preparation.prepared_operation.remote_gateway_required);
        assert!(!preparation.gateway_plaintext_access);
    }

    #[test]
    fn adapter_rejects_get_with_plaintext_body() {
        let err = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            plaintext_body: Some(b"bad".to_vec()),
            ..request_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessRequestAdapterError::Service(_)));
    }

    #[test]
    fn adapter_rejects_missing_bucket_identity_context() {
        let err = LocalTrustlessRequestAdapter::prepare(LocalTrustlessRequestInput {
            bucket_id: " ".to_owned(),
            ..request_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, LocalTrustlessRequestAdapterError::Service(_)));
    }
}
