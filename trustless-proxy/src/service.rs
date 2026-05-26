use thiserror::Error;

use crate::execution_coordinator::{
    TrustlessExecutionBoundaryRequirements, TrustlessExecutionCoordinator,
    TrustlessExecutionCoordinatorError, TrustlessExecutionResult,
};
use crate::pipeline::{
    TrustlessLocalPipeline, TrustlessPipelineError, TrustlessPipelineInput, TrustlessPipelinePlan,
};
use crate::router::TrustlessExecutionStage;
use crate::s3_surface::{LocalS3Operation, LocalS3Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustlessLocalServiceNextAction {
    SendCiphertextOnlyRemoteRequest,
    AwaitCiphertextThenDecryptLocally,
    CreateTrustlessBucketAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessLocalServicePreparedOperation {
    pub operation: LocalS3Operation,
    pub pipeline_plan: TrustlessPipelinePlan,
    pub boundary_requirements: TrustlessExecutionBoundaryRequirements,
    pub expected_local_response: Option<LocalS3Response>,
    pub next_action: TrustlessLocalServiceNextAction,
    pub plaintext_body_available_locally: bool,
    pub remote_gateway_required: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessLocalServiceError {
    #[error(transparent)]
    Pipeline(TrustlessPipelineError),

    #[error(transparent)]
    ExecutionCoordinator(TrustlessExecutionCoordinatorError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("prepared operation must be GET to complete local plaintext response")]
    PreparedOperationIsNotGet,

    #[error("GET prepared operation must not already contain a local response")]
    PreparedGetAlreadyHasLocalResponse,
}

impl From<TrustlessPipelineError> for TrustlessLocalServiceError {
    fn from(error: TrustlessPipelineError) -> Self {
        Self::Pipeline(error)
    }
}

impl From<TrustlessExecutionCoordinatorError> for TrustlessLocalServiceError {
    fn from(error: TrustlessExecutionCoordinatorError) -> Self {
        Self::ExecutionCoordinator(error)
    }
}

pub struct TrustlessLocalService;

impl TrustlessLocalService {
    pub fn prepare(
        input: TrustlessPipelineInput,
    ) -> Result<TrustlessLocalServicePreparedOperation, TrustlessLocalServiceError> {
        let plan = TrustlessLocalPipeline::plan(input)?;

        if plan.gateway_plaintext_access {
            return Err(TrustlessLocalServiceError::GatewayPlaintextAccessRejected);
        }

        match plan.operation {
            LocalS3Operation::GetObject => prepare_pending_get(plan),
            LocalS3Operation::CreateTrustlessBucket => prepare_metadata_operation(
                plan,
                TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor,
            ),
            LocalS3Operation::PutObject
            | LocalS3Operation::HeadObject
            | LocalS3Operation::ListObjectsV2
            | LocalS3Operation::DeleteObject => prepare_metadata_operation(
                plan,
                TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest,
            ),
        }
    }

    pub fn complete_get_with_plaintext(
        prepared: TrustlessLocalServicePreparedOperation,
        plaintext: Vec<u8>,
    ) -> Result<TrustlessExecutionResult, TrustlessLocalServiceError> {
        if prepared.operation != LocalS3Operation::GetObject {
            return Err(TrustlessLocalServiceError::PreparedOperationIsNotGet);
        }

        if prepared.expected_local_response.is_some() {
            return Err(TrustlessLocalServiceError::PreparedGetAlreadyHasLocalResponse);
        }

        Ok(
            TrustlessExecutionCoordinator::coordinate_get_plaintext_response(
                prepared.pipeline_plan,
                plaintext,
            )?,
        )
    }
}

fn prepare_pending_get(
    plan: TrustlessPipelinePlan,
) -> Result<TrustlessLocalServicePreparedOperation, TrustlessLocalServiceError> {
    if plan.gateway_plaintext_access
        || plan.route.gateway_plaintext_access
        || plan.request_context.gateway_plaintext_access
    {
        return Err(TrustlessLocalServiceError::GatewayPlaintextAccessRejected);
    }

    if !plan
        .stages
        .contains(&TrustlessExecutionStage::DecryptObjectLocally)
        || !plan
            .stages
            .contains(&TrustlessExecutionStage::ReturnLocalPlaintext)
    {
        return Err(TrustlessExecutionCoordinatorError::MissingExecutionStage(
            TrustlessExecutionStage::ReturnLocalPlaintext,
        )
        .into());
    }

    Ok(TrustlessLocalServicePreparedOperation {
        operation: plan.operation,
        boundary_requirements: get_boundary_requirements(&plan),
        expected_local_response: None,
        next_action: TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally,
        plaintext_body_available_locally: plan.plaintext_body_available_locally,
        remote_gateway_required: plan.remote_gateway_required,
        gateway_plaintext_access: false,
        pipeline_plan: plan,
    })
}

fn prepare_metadata_operation(
    plan: TrustlessPipelinePlan,
    next_action: TrustlessLocalServiceNextAction,
) -> Result<TrustlessLocalServicePreparedOperation, TrustlessLocalServiceError> {
    let result = TrustlessExecutionCoordinator::coordinate_metadata_response(plan)?;
    let remote_gateway_required = result.boundary_requirements.remote_gateway_required;

    Ok(TrustlessLocalServicePreparedOperation {
        operation: result.operation,
        pipeline_plan: result.pipeline_plan,
        boundary_requirements: result.boundary_requirements,
        expected_local_response: Some(result.local_response),
        next_action,
        plaintext_body_available_locally: false,
        remote_gateway_required,
        gateway_plaintext_access: false,
    })
}

fn get_boundary_requirements(
    plan: &TrustlessPipelinePlan,
) -> TrustlessExecutionBoundaryRequirements {
    TrustlessExecutionBoundaryRequirements {
        preflight_required: plan
            .stages
            .contains(&TrustlessExecutionStage::BuildOperationPreflight),
        operation_assembly_required: true,
        remote_gateway_required: plan.remote_gateway_required,
        local_response_required: true,
        operation_assembler_boundary: Some("TrustlessOperationAssembler"),
        remote_gateway_executor_boundary: plan
            .remote_gateway_required
            .then_some("TrustlessRemoteGatewayExecutor"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_surface::LocalS3Request;

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
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    #[test]
    fn service_prepares_put_for_ciphertext_only_remote_request() {
        let prepared = TrustlessLocalService::prepare(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                plaintext_body: Some(b"secret".to_vec()),
                plaintext_body_allowed_locally: true,
                ..s3_request(LocalS3Operation::PutObject)
            },
            ..pipeline_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::PutObject);
        assert_eq!(
            prepared.next_action,
            TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
        );
        assert!(prepared.remote_gateway_required);
        assert!(prepared.boundary_requirements.preflight_required);
        assert!(prepared.boundary_requirements.operation_assembly_required);
        assert!(prepared.boundary_requirements.remote_gateway_required);
        assert_eq!(
            prepared.boundary_requirements.operation_assembler_boundary,
            Some("TrustlessOperationAssembler")
        );
        assert_eq!(
            prepared
                .boundary_requirements
                .remote_gateway_executor_boundary,
            Some("TrustlessRemoteGatewayExecutor")
        );
        assert!(prepared.expected_local_response.unwrap().metadata_only);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn service_prepares_get_awaiting_ciphertext_and_local_decrypt() {
        let prepared =
            TrustlessLocalService::prepare(pipeline_input(LocalS3Operation::GetObject)).unwrap();

        assert_eq!(prepared.operation, LocalS3Operation::GetObject);
        assert_eq!(
            prepared.next_action,
            TrustlessLocalServiceNextAction::AwaitCiphertextThenDecryptLocally
        );
        assert!(prepared.expected_local_response.is_none());
        assert!(prepared.remote_gateway_required);
        assert!(prepared.boundary_requirements.operation_assembly_required);
        assert_eq!(
            prepared
                .boundary_requirements
                .remote_gateway_executor_boundary,
            Some("TrustlessRemoteGatewayExecutor")
        );
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn service_completes_get_with_local_plaintext_response() {
        let prepared =
            TrustlessLocalService::prepare(pipeline_input(LocalS3Operation::GetObject)).unwrap();

        let result =
            TrustlessLocalService::complete_get_with_plaintext(prepared, b"secret".to_vec())
                .unwrap();

        assert_eq!(result.operation, LocalS3Operation::GetObject);
        assert_eq!(
            result.local_response.plaintext_body,
            Some(b"secret".to_vec())
        );
        assert!(result.local_response.plaintext_returned_locally);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn service_prepares_head_list_and_delete_as_metadata_remote_operations() {
        for operation in [LocalS3Operation::HeadObject, LocalS3Operation::DeleteObject] {
            let prepared = TrustlessLocalService::prepare(pipeline_input(operation)).unwrap();

            assert_eq!(prepared.operation, operation);
            assert_eq!(
                prepared.next_action,
                TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
            );
            assert!(prepared.remote_gateway_required);
            assert!(prepared.expected_local_response.unwrap().metadata_only);
            assert!(!prepared.gateway_plaintext_access);
        }

        let list_prepared = TrustlessLocalService::prepare(TrustlessPipelineInput {
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

        assert_eq!(list_prepared.operation, LocalS3Operation::ListObjectsV2);
        assert_eq!(
            list_prepared.next_action,
            TrustlessLocalServiceNextAction::SendCiphertextOnlyRemoteRequest
        );
        assert!(list_prepared.remote_gateway_required);
        assert!(list_prepared.expected_local_response.unwrap().metadata_only);
    }

    #[test]
    fn service_prepares_create_bucket_anchor_without_remote_gateway() {
        let prepared = TrustlessLocalService::prepare(TrustlessPipelineInput {
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

        assert_eq!(prepared.operation, LocalS3Operation::CreateTrustlessBucket);
        assert_eq!(
            prepared.next_action,
            TrustlessLocalServiceNextAction::CreateTrustlessBucketAnchor
        );
        assert!(!prepared.remote_gateway_required);
        assert!(
            prepared
                .boundary_requirements
                .remote_gateway_executor_boundary
                .is_none()
        );
        assert!(prepared.expected_local_response.unwrap().metadata_only);
        assert!(!prepared.gateway_plaintext_access);
    }

    #[test]
    fn service_rejects_plaintext_outside_put_boundary() {
        let err = TrustlessLocalService::prepare(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                plaintext_body: Some(b"bad".to_vec()),
                ..s3_request(LocalS3Operation::GetObject)
            },
            ..pipeline_input(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert!(matches!(err, TrustlessLocalServiceError::Pipeline(_)));
    }

    #[test]
    fn service_rejects_completing_non_get_as_plaintext_response() {
        let prepared = TrustlessLocalService::prepare(TrustlessPipelineInput {
            s3_request: LocalS3Request {
                plaintext_body: Some(b"secret".to_vec()),
                plaintext_body_allowed_locally: true,
                ..s3_request(LocalS3Operation::PutObject)
            },
            ..pipeline_input(LocalS3Operation::PutObject)
        })
        .unwrap();

        let err = TrustlessLocalService::complete_get_with_plaintext(prepared, b"secret".to_vec())
            .unwrap_err();

        assert_eq!(err, TrustlessLocalServiceError::PreparedOperationIsNotGet);
    }
}
