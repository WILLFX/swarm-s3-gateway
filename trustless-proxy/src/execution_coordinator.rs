use thiserror::Error;

use crate::gateway_boundary::{
    CiphertextGatewayBoundary, CiphertextGatewayBoundaryError, CiphertextGatewayResponse,
};
use crate::pipeline::TrustlessPipelinePlan;
use crate::planner::RemoteGatewayAction;
use crate::router::TrustlessExecutionStage;
use crate::s3_surface::{LocalS3Operation, LocalS3Response, LocalS3Surface, LocalS3SurfaceError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessExecutionBoundaryRequirements {
    pub preflight_required: bool,
    pub operation_assembly_required: bool,
    pub remote_gateway_required: bool,
    pub local_response_required: bool,
    pub operation_assembler_boundary: Option<&'static str>,
    pub remote_gateway_executor_boundary: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessExecutionResult {
    pub operation: LocalS3Operation,
    pub pipeline_plan: TrustlessPipelinePlan,
    pub boundary_requirements: TrustlessExecutionBoundaryRequirements,
    pub local_response: LocalS3Response,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessExecutionCoordinatorError {
    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("missing execution stage: {0:?}")]
    MissingExecutionStage(TrustlessExecutionStage),

    #[error("GET requires a local plaintext result after local decryption")]
    MissingGetPlaintextResult,

    #[error("local plaintext response is only valid for GET")]
    UnexpectedLocalPlaintextResponse,

    #[error("remote gateway response was not expected for this operation")]
    UnexpectedRemoteGatewayResponse,

    #[error("remote gateway action mismatch, expected {expected:?}, got {actual:?}")]
    RemoteActionMismatch {
        expected: RemoteGatewayAction,
        actual: RemoteGatewayAction,
    },

    #[error(transparent)]
    LocalS3Surface(LocalS3SurfaceError),

    #[error(transparent)]
    GatewayBoundary(CiphertextGatewayBoundaryError),
}

impl From<LocalS3SurfaceError> for TrustlessExecutionCoordinatorError {
    fn from(error: LocalS3SurfaceError) -> Self {
        Self::LocalS3Surface(error)
    }
}

impl From<CiphertextGatewayBoundaryError> for TrustlessExecutionCoordinatorError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::GatewayBoundary(error)
    }
}

pub struct TrustlessExecutionCoordinator;

impl TrustlessExecutionCoordinator {
    pub fn coordinate_metadata_response(
        plan: TrustlessPipelinePlan,
    ) -> Result<TrustlessExecutionResult, TrustlessExecutionCoordinatorError> {
        validate_plan(&plan)?;

        if plan.operation == LocalS3Operation::GetObject {
            return Err(TrustlessExecutionCoordinatorError::MissingGetPlaintextResult);
        }

        require_stage(&plan, TrustlessExecutionStage::ReturnMetadataOnly)?;

        let response = LocalS3Surface::metadata_only_response(plan.operation)?;
        LocalS3Surface::validate_no_gateway_plaintext(&response)?;

        build_result(plan, response)
    }

    pub fn coordinate_get_plaintext_response(
        plan: TrustlessPipelinePlan,
        plaintext: Vec<u8>,
    ) -> Result<TrustlessExecutionResult, TrustlessExecutionCoordinatorError> {
        validate_plan(&plan)?;

        if plan.operation != LocalS3Operation::GetObject {
            return Err(TrustlessExecutionCoordinatorError::UnexpectedLocalPlaintextResponse);
        }

        require_stage(&plan, TrustlessExecutionStage::DecryptObjectLocally)?;
        require_stage(&plan, TrustlessExecutionStage::ReturnLocalPlaintext)?;

        let response = LocalS3Surface::local_plaintext_response(plan.operation, plaintext)?;
        LocalS3Surface::validate_no_gateway_plaintext(&response)?;

        build_result(plan, response)
    }

    pub fn validate_remote_gateway_response(
        plan: &TrustlessPipelinePlan,
        response: CiphertextGatewayResponse,
    ) -> Result<CiphertextGatewayResponse, TrustlessExecutionCoordinatorError> {
        validate_plan(plan)?;

        if !plan.remote_gateway_required {
            return Err(TrustlessExecutionCoordinatorError::UnexpectedRemoteGatewayResponse);
        }

        require_stage(
            plan,
            TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
        )?;

        let response = CiphertextGatewayBoundary::validate_response(response)?;

        let Some(expected) = expected_remote_action(plan.operation) else {
            return Err(TrustlessExecutionCoordinatorError::UnexpectedRemoteGatewayResponse);
        };

        if response.action != expected {
            return Err(TrustlessExecutionCoordinatorError::RemoteActionMismatch {
                expected,
                actual: response.action,
            });
        }

        Ok(response)
    }
}

fn build_result(
    plan: TrustlessPipelinePlan,
    local_response: LocalS3Response,
) -> Result<TrustlessExecutionResult, TrustlessExecutionCoordinatorError> {
    let operation = plan.operation;
    let boundary_requirements = boundary_requirements_for(&plan);

    Ok(TrustlessExecutionResult {
        operation,
        pipeline_plan: plan,
        boundary_requirements,
        local_response,
        gateway_plaintext_access: false,
    })
}

fn validate_plan(plan: &TrustlessPipelinePlan) -> Result<(), TrustlessExecutionCoordinatorError> {
    if plan.gateway_plaintext_access
        || plan.route.gateway_plaintext_access
        || plan.request_context.gateway_plaintext_access
    {
        return Err(TrustlessExecutionCoordinatorError::GatewayPlaintextAccessRejected);
    }

    require_stage(plan, TrustlessExecutionStage::BuildTrustlessRequestContext)?;

    Ok(())
}

fn require_stage(
    plan: &TrustlessPipelinePlan,
    stage: TrustlessExecutionStage,
) -> Result<(), TrustlessExecutionCoordinatorError> {
    if !plan.stages.contains(&stage) {
        return Err(TrustlessExecutionCoordinatorError::MissingExecutionStage(
            stage,
        ));
    }

    Ok(())
}

fn boundary_requirements_for(
    plan: &TrustlessPipelinePlan,
) -> TrustlessExecutionBoundaryRequirements {
    let operation_assembly_required = matches!(
        plan.operation,
        LocalS3Operation::PutObject
            | LocalS3Operation::GetObject
            | LocalS3Operation::ListObjectsV2
            | LocalS3Operation::DeleteObject
    );

    TrustlessExecutionBoundaryRequirements {
        preflight_required: plan
            .stages
            .contains(&TrustlessExecutionStage::BuildOperationPreflight),
        operation_assembly_required,
        remote_gateway_required: plan.remote_gateway_required,
        local_response_required: true,
        operation_assembler_boundary: operation_assembly_required
            .then_some("TrustlessOperationAssembler"),
        remote_gateway_executor_boundary: plan
            .remote_gateway_required
            .then_some("TrustlessRemoteGatewayExecutor"),
    }
}

fn expected_remote_action(operation: LocalS3Operation) -> Option<RemoteGatewayAction> {
    match operation {
        LocalS3Operation::PutObject => Some(RemoteGatewayAction::PutCiphertextObject),
        LocalS3Operation::GetObject => Some(RemoteGatewayAction::GetCiphertextObject),
        LocalS3Operation::HeadObject => Some(RemoteGatewayAction::HeadCiphertextObject),
        LocalS3Operation::ListObjectsV2 => Some(RemoteGatewayAction::ListCiphertextManifest),
        LocalS3Operation::DeleteObject => Some(RemoteGatewayAction::DeleteCiphertextObject),
        LocalS3Operation::CreateTrustlessBucket => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{TrustlessLocalPipeline, TrustlessPipelineInput};
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

    fn pipeline_plan(operation: LocalS3Operation) -> TrustlessPipelinePlan {
        match operation {
            LocalS3Operation::PutObject => TrustlessLocalPipeline::plan(TrustlessPipelineInput {
                s3_request: LocalS3Request {
                    plaintext_body: Some(b"secret".to_vec()),
                    plaintext_body_allowed_locally: true,
                    ..s3_request(LocalS3Operation::PutObject)
                },
                ..pipeline_input(LocalS3Operation::PutObject)
            })
            .unwrap(),
            LocalS3Operation::ListObjectsV2 => {
                TrustlessLocalPipeline::plan(TrustlessPipelineInput {
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
                .unwrap()
            }
            LocalS3Operation::CreateTrustlessBucket => {
                TrustlessLocalPipeline::plan(TrustlessPipelineInput {
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
                .unwrap()
            }
            _ => TrustlessLocalPipeline::plan(pipeline_input(operation)).unwrap(),
        }
    }

    fn remote_response(action: RemoteGatewayAction) -> CiphertextGatewayResponse {
        CiphertextGatewayResponse {
            action,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            metadata_only: true,
            gateway_plaintext_access: false,
        }
    }

    #[test]
    fn coordinator_returns_metadata_for_put_after_ciphertext_remote_stage() {
        let result = TrustlessExecutionCoordinator::coordinate_metadata_response(pipeline_plan(
            LocalS3Operation::PutObject,
        ))
        .unwrap();

        assert_eq!(result.operation, LocalS3Operation::PutObject);
        assert!(result.local_response.metadata_only);
        assert!(result.local_response.plaintext_body.is_none());
        assert!(result.boundary_requirements.preflight_required);
        assert!(result.boundary_requirements.operation_assembly_required);
        assert!(result.boundary_requirements.remote_gateway_required);
        assert_eq!(
            result.boundary_requirements.operation_assembler_boundary,
            Some("TrustlessOperationAssembler")
        );
        assert_eq!(
            result
                .boundary_requirements
                .remote_gateway_executor_boundary,
            Some("TrustlessRemoteGatewayExecutor")
        );
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn coordinator_returns_local_plaintext_for_get_after_decrypt_stage() {
        let result = TrustlessExecutionCoordinator::coordinate_get_plaintext_response(
            pipeline_plan(LocalS3Operation::GetObject),
            b"secret".to_vec(),
        )
        .unwrap();

        assert_eq!(result.operation, LocalS3Operation::GetObject);
        assert_eq!(
            result.local_response.plaintext_body,
            Some(b"secret".to_vec())
        );
        assert!(result.local_response.plaintext_returned_locally);
        assert!(result.boundary_requirements.operation_assembly_required);
        assert!(result.boundary_requirements.remote_gateway_required);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn coordinator_returns_metadata_for_head_list_delete_and_create() {
        for operation in [
            LocalS3Operation::HeadObject,
            LocalS3Operation::ListObjectsV2,
            LocalS3Operation::DeleteObject,
            LocalS3Operation::CreateTrustlessBucket,
        ] {
            let result = TrustlessExecutionCoordinator::coordinate_metadata_response(
                pipeline_plan(operation),
            )
            .unwrap();

            assert_eq!(result.operation, operation);
            assert!(result.local_response.metadata_only);
            assert!(result.local_response.plaintext_body.is_none());
            assert!(!result.gateway_plaintext_access);
        }
    }

    #[test]
    fn coordinator_validates_ciphertext_only_remote_gateway_response() {
        let plan = pipeline_plan(LocalS3Operation::GetObject);

        let response = TrustlessExecutionCoordinator::validate_remote_gateway_response(
            &plan,
            CiphertextGatewayResponse {
                ciphertext_payload: Some(b"ciphertext".to_vec()),
                metadata_only: false,
                ..remote_response(RemoteGatewayAction::GetCiphertextObject)
            },
        )
        .unwrap();

        assert_eq!(response.action, RemoteGatewayAction::GetCiphertextObject);
        assert_eq!(response.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(!response.gateway_plaintext_access);
    }

    #[test]
    fn coordinator_rejects_gateway_plaintext_remote_response() {
        let plan = pipeline_plan(LocalS3Operation::GetObject);

        let err = TrustlessExecutionCoordinator::validate_remote_gateway_response(
            &plan,
            CiphertextGatewayResponse {
                gateway_plaintext_access: true,
                ..remote_response(RemoteGatewayAction::GetCiphertextObject)
            },
        )
        .unwrap_err();

        assert!(matches!(
            err,
            TrustlessExecutionCoordinatorError::GatewayBoundary(_)
        ));
    }

    #[test]
    fn coordinator_rejects_remote_action_mismatch() {
        let plan = pipeline_plan(LocalS3Operation::GetObject);

        let err = TrustlessExecutionCoordinator::validate_remote_gateway_response(
            &plan,
            remote_response(RemoteGatewayAction::PutCiphertextObject),
        )
        .unwrap_err();

        assert_eq!(
            err,
            TrustlessExecutionCoordinatorError::RemoteActionMismatch {
                expected: RemoteGatewayAction::GetCiphertextObject,
                actual: RemoteGatewayAction::PutCiphertextObject,
            }
        );
    }

    #[test]
    fn coordinator_rejects_metadata_response_for_get_without_plaintext() {
        let err = TrustlessExecutionCoordinator::coordinate_metadata_response(pipeline_plan(
            LocalS3Operation::GetObject,
        ))
        .unwrap_err();

        assert_eq!(
            err,
            TrustlessExecutionCoordinatorError::MissingGetPlaintextResult
        );
    }

    #[test]
    fn coordinator_rejects_plaintext_response_for_non_get_operation() {
        let err = TrustlessExecutionCoordinator::coordinate_get_plaintext_response(
            pipeline_plan(LocalS3Operation::PutObject),
            b"secret".to_vec(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            TrustlessExecutionCoordinatorError::UnexpectedLocalPlaintextResponse
        );
    }

    #[test]
    fn coordinator_handles_create_bucket_without_remote_gateway() {
        let result = TrustlessExecutionCoordinator::coordinate_metadata_response(pipeline_plan(
            LocalS3Operation::CreateTrustlessBucket,
        ))
        .unwrap();

        assert_eq!(result.operation, LocalS3Operation::CreateTrustlessBucket);
        assert!(!result.boundary_requirements.remote_gateway_required);
        assert!(
            result
                .boundary_requirements
                .remote_gateway_executor_boundary
                .is_none()
        );
        assert!(!result.boundary_requirements.operation_assembly_required);
        assert!(result.local_response.metadata_only);
        assert!(!result.gateway_plaintext_access);
    }
}
