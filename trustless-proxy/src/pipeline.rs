use thiserror::Error;

use crate::request_context::{
    TrustlessRequestContext, TrustlessRequestContextBuilder, TrustlessRequestContextError,
    TrustlessRequestContextInput,
};
use crate::router::{
    TrustlessExecutionStage, TrustlessLocalOperationRoute, TrustlessLocalOperationRouter,
    TrustlessRouterError,
};
use crate::s3_surface::{LocalS3Operation, LocalS3Request};
use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPipelineInput {
    pub s3_request: LocalS3Request,
    pub bucket_id: String,
    pub object_key_id: Option<String>,
    pub policy_version: u32,
    pub local_account: SubstrateAccountId,
    pub local_key_type: String,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPipelinePlan {
    pub operation: LocalS3Operation,
    pub route: TrustlessLocalOperationRoute,
    pub request_context: TrustlessRequestContext,
    pub stages: Vec<TrustlessExecutionStage>,
    pub plaintext_body_available_locally: bool,
    pub remote_gateway_required: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessPipelineError {
    #[error(transparent)]
    Router(TrustlessRouterError),

    #[error(transparent)]
    RequestContext(TrustlessRequestContextError),

    #[error("pipeline route and context operation mismatch")]
    OperationMismatch,

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,
}

impl From<TrustlessRouterError> for TrustlessPipelineError {
    fn from(error: TrustlessRouterError) -> Self {
        Self::Router(error)
    }
}

impl From<TrustlessRequestContextError> for TrustlessPipelineError {
    fn from(error: TrustlessRequestContextError) -> Self {
        Self::RequestContext(error)
    }
}

pub struct TrustlessLocalPipeline;

impl TrustlessLocalPipeline {
    pub fn plan(
        input: TrustlessPipelineInput,
    ) -> Result<TrustlessPipelinePlan, TrustlessPipelineError> {
        let route = TrustlessLocalOperationRouter::route_request(input.s3_request)?;

        if route.gateway_plaintext_access {
            return Err(TrustlessPipelineError::GatewayPlaintextAccessRejected);
        }

        let request_context =
            TrustlessRequestContextBuilder::build(TrustlessRequestContextInput {
                route_intent: route.route_intent.clone(),
                bucket_id: input.bucket_id,
                object_key_id: input.object_key_id,
                policy_version: input.policy_version,
                local_account: input.local_account,
                local_key_type: input.local_key_type,
                recipients: input.recipients,
            })?;

        if request_context.gateway_plaintext_access {
            return Err(TrustlessPipelineError::GatewayPlaintextAccessRejected);
        }

        if route.operation != request_context.local_operation {
            return Err(TrustlessPipelineError::OperationMismatch);
        }

        Ok(TrustlessPipelinePlan {
            operation: route.operation,
            stages: route.stages.clone(),
            plaintext_body_available_locally: request_context.plaintext_body.is_some(),
            remote_gateway_required: route.remote_gateway_required,
            gateway_plaintext_access: false,
            route,
            request_context,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_surface::{LocalS3Operation, LocalS3Request};

    fn s3_request(operation: LocalS3Operation) -> LocalS3Request {
        LocalS3Request {
            operation,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        }
    }

    fn pipeline_input(operation: LocalS3Operation) -> TrustlessPipelineInput {
        TrustlessPipelineInput {
            s3_request: s3_request(operation),
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["bob".to_owned(), "alice".to_owned()],
        }
    }

    #[test]
    fn pipeline_plans_put_from_local_plaintext_to_ciphertext_gateway_stages() {
        let plan = TrustlessLocalPipeline::plan(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                plaintext_body: Some(b"secret".to_vec()),
                plaintext_body_allowed_locally: true,
                ..s3_request(LocalS3Operation::PutObject)
            },
            ..pipeline_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(plan.operation, LocalS3Operation::PutObject);
        assert!(plan.plaintext_body_available_locally);
        assert!(plan.remote_gateway_required);
        assert!(!plan.gateway_plaintext_access);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::EncryptObjectLocally)
        );
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest)
        );
    }

    #[test]
    fn pipeline_plans_get_with_local_decrypt_and_plaintext_return_stage() {
        let plan =
            TrustlessLocalPipeline::plan(pipeline_input(LocalS3Operation::GetObject)).unwrap();

        assert_eq!(plan.operation, LocalS3Operation::GetObject);
        assert!(!plan.plaintext_body_available_locally);
        assert!(plan.remote_gateway_required);
        assert!(!plan.gateway_plaintext_access);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::DecryptObjectLocally)
        );
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::ReturnLocalPlaintext)
        );
    }

    #[test]
    fn pipeline_plans_head_as_metadata_only() {
        let plan =
            TrustlessLocalPipeline::plan(pipeline_input(LocalS3Operation::HeadObject)).unwrap();

        assert_eq!(plan.operation, LocalS3Operation::HeadObject);
        assert!(!plan.plaintext_body_available_locally);
        assert!(plan.remote_gateway_required);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::ReturnMetadataOnly)
        );
        assert!(
            !plan
                .stages
                .contains(&TrustlessExecutionStage::DecryptObjectLocally)
        );
    }

    #[test]
    fn pipeline_plans_list_without_object_key_id() {
        let plan = TrustlessLocalPipeline::plan(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                operation: LocalS3Operation::ListObjectsV2,
                bucket: "bucket".to_owned(),
                key: None,
                prefix: Some("docs/".to_owned()),
                plaintext_body: None,
                plaintext_body_allowed_locally: false,
            },
            object_key_id: None,
            ..pipeline_input(LocalS3Operation::ListObjectsV2)
        })
        .unwrap();

        assert_eq!(plan.operation, LocalS3Operation::ListObjectsV2);
        assert!(plan.remote_gateway_required);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::DecryptManifestLocally)
        );
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::ReturnMetadataOnly)
        );
        assert!(
            plan.request_context
                .preflight_request
                .object_key_id
                .is_none()
        );
    }

    #[test]
    fn pipeline_plans_delete_with_local_manifest_mutation() {
        let plan =
            TrustlessLocalPipeline::plan(pipeline_input(LocalS3Operation::DeleteObject)).unwrap();

        assert_eq!(plan.operation, LocalS3Operation::DeleteObject);
        assert!(plan.remote_gateway_required);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::MutateManifestLocally)
        );
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::EncryptManifestLocally)
        );
        assert!(!plan.gateway_plaintext_access);
    }

    #[test]
    fn pipeline_plans_create_bucket_without_remote_gateway() {
        let plan = TrustlessLocalPipeline::plan(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                operation: LocalS3Operation::CreateTrustlessBucket,
                bucket: "bucket".to_owned(),
                key: None,
                prefix: None,
                plaintext_body: None,
                plaintext_body_allowed_locally: false,
            },
            object_key_id: None,
            ..pipeline_input(LocalS3Operation::CreateTrustlessBucket)
        })
        .unwrap();

        assert_eq!(plan.operation, LocalS3Operation::CreateTrustlessBucket);
        assert!(!plan.remote_gateway_required);
        assert!(
            plan.stages
                .contains(&TrustlessExecutionStage::CreateTrustlessBucketAnchor)
        );
        assert!(!plan.gateway_plaintext_access);
    }

    #[test]
    fn pipeline_rejects_plaintext_outside_put_boundary() {
        let err = TrustlessLocalPipeline::plan(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                plaintext_body: Some(b"bad".to_vec()),
                ..s3_request(LocalS3Operation::GetObject)
            },
            ..pipeline_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, TrustlessPipelineError::Router(_)));
    }

    #[test]
    fn pipeline_rejects_missing_context_identity_fields() {
        let err = TrustlessLocalPipeline::plan(TrustlessPipelineInput {
            bucket_id: " ".to_owned(),
            ..pipeline_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert_eq!(
            err,
            TrustlessPipelineError::RequestContext(TrustlessRequestContextError::MissingBucketId)
        );
    }
}
