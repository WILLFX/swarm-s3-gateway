use thiserror::Error;

use crate::s3_surface::{
    LocalS3Operation, LocalS3Request, LocalS3RouteIntent, LocalS3Surface, LocalS3SurfaceError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustlessExecutionStage {
    ClassifyLocalS3Request,
    BuildTrustlessRequestContext,
    ResolveRecipientKeys,
    SelectLocalPrivateKey,
    BuildOperationPreflight,
    EncryptObjectLocally,
    DecryptObjectLocally,
    ReadEncryptedManifest,
    DecryptManifestLocally,
    MutateManifestLocally,
    EncryptManifestLocally,
    SendCiphertextOnlyGatewayRequest,
    ReturnLocalPlaintext,
    ReturnMetadataOnly,
    CreateTrustlessBucketAnchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessLocalOperationRoute {
    pub operation: LocalS3Operation,
    pub route_intent: LocalS3RouteIntent,
    pub stages: Vec<TrustlessExecutionStage>,
    pub plaintext_allowed_only_at_local_boundary: bool,
    pub remote_gateway_required: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessRouterError {
    #[error(transparent)]
    LocalS3Surface(LocalS3SurfaceError),

    #[error("gateway plaintext access is not allowed")]
    GatewayPlaintextAccessRejected,

    #[error("PUT route must allow plaintext only at the local boundary")]
    InvalidPutPlaintextBoundary,
}

impl From<LocalS3SurfaceError> for TrustlessRouterError {
    fn from(error: LocalS3SurfaceError) -> Self {
        Self::LocalS3Surface(error)
    }
}

pub struct TrustlessLocalOperationRouter;

impl TrustlessLocalOperationRouter {
    pub fn route_request(
        request: LocalS3Request,
    ) -> Result<TrustlessLocalOperationRoute, TrustlessRouterError> {
        let route_intent = LocalS3Surface::classify_request(request)?;
        Self::route_intent(route_intent)
    }

    pub fn route_intent(
        route_intent: LocalS3RouteIntent,
    ) -> Result<TrustlessLocalOperationRoute, TrustlessRouterError> {
        if route_intent.gateway_plaintext_access {
            return Err(TrustlessRouterError::GatewayPlaintextAccessRejected);
        }

        let operation = route_intent.operation;

        if operation == LocalS3Operation::PutObject
            && (!route_intent.plaintext_body_allowed_locally
                || route_intent.plaintext_body.is_none())
        {
            return Err(TrustlessRouterError::InvalidPutPlaintextBoundary);
        }

        let stages = match operation {
            LocalS3Operation::PutObject => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::ResolveRecipientKeys,
                TrustlessExecutionStage::SelectLocalPrivateKey,
                TrustlessExecutionStage::BuildOperationPreflight,
                TrustlessExecutionStage::EncryptObjectLocally,
                TrustlessExecutionStage::ReadEncryptedManifest,
                TrustlessExecutionStage::DecryptManifestLocally,
                TrustlessExecutionStage::MutateManifestLocally,
                TrustlessExecutionStage::EncryptManifestLocally,
                TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
                TrustlessExecutionStage::ReturnMetadataOnly,
            ],
            LocalS3Operation::GetObject => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::SelectLocalPrivateKey,
                TrustlessExecutionStage::BuildOperationPreflight,
                TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
                TrustlessExecutionStage::DecryptObjectLocally,
                TrustlessExecutionStage::ReturnLocalPlaintext,
            ],
            LocalS3Operation::HeadObject => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::BuildOperationPreflight,
                TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
                TrustlessExecutionStage::ReturnMetadataOnly,
            ],
            LocalS3Operation::ListObjectsV2 => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::SelectLocalPrivateKey,
                TrustlessExecutionStage::BuildOperationPreflight,
                TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
                TrustlessExecutionStage::ReadEncryptedManifest,
                TrustlessExecutionStage::DecryptManifestLocally,
                TrustlessExecutionStage::ReturnMetadataOnly,
            ],
            LocalS3Operation::DeleteObject => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::SelectLocalPrivateKey,
                TrustlessExecutionStage::BuildOperationPreflight,
                TrustlessExecutionStage::ReadEncryptedManifest,
                TrustlessExecutionStage::DecryptManifestLocally,
                TrustlessExecutionStage::MutateManifestLocally,
                TrustlessExecutionStage::EncryptManifestLocally,
                TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest,
                TrustlessExecutionStage::ReturnMetadataOnly,
            ],
            LocalS3Operation::CreateTrustlessBucket => vec![
                TrustlessExecutionStage::ClassifyLocalS3Request,
                TrustlessExecutionStage::BuildTrustlessRequestContext,
                TrustlessExecutionStage::CreateTrustlessBucketAnchor,
                TrustlessExecutionStage::ReturnMetadataOnly,
            ],
        };

        let remote_gateway_required = matches!(
            operation,
            LocalS3Operation::PutObject
                | LocalS3Operation::GetObject
                | LocalS3Operation::HeadObject
                | LocalS3Operation::ListObjectsV2
                | LocalS3Operation::DeleteObject
        );

        Ok(TrustlessLocalOperationRoute {
            operation,
            route_intent,
            stages,
            plaintext_allowed_only_at_local_boundary: true,
            remote_gateway_required,
            gateway_plaintext_access: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(operation: LocalS3Operation) -> LocalS3Request {
        LocalS3Request {
            operation,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        }
    }

    #[test]
    fn put_route_keeps_plaintext_at_local_boundary_then_encrypts_and_forwards_ciphertext() {
        let route = TrustlessLocalOperationRouter::route_request(LocalS3Request {
            plaintext_body: Some(b"secret".to_vec()),
            plaintext_body_allowed_locally: true,
            ..request(LocalS3Operation::PutObject)
        })
        .unwrap();

        assert_eq!(route.operation, LocalS3Operation::PutObject);
        assert!(route.plaintext_allowed_only_at_local_boundary);
        assert!(route.remote_gateway_required);
        assert!(!route.gateway_plaintext_access);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::EncryptObjectLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::EncryptManifestLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest)
        );
    }

    #[test]
    fn get_route_fetches_ciphertext_and_returns_plaintext_locally() {
        let route =
            TrustlessLocalOperationRouter::route_request(request(LocalS3Operation::GetObject))
                .unwrap();

        assert_eq!(route.operation, LocalS3Operation::GetObject);
        assert!(route.remote_gateway_required);
        assert!(!route.gateway_plaintext_access);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::DecryptObjectLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::ReturnLocalPlaintext)
        );
    }

    #[test]
    fn head_route_returns_metadata_only_without_local_decrypt_stage() {
        let route =
            TrustlessLocalOperationRouter::route_request(request(LocalS3Operation::HeadObject))
                .unwrap();

        assert_eq!(route.operation, LocalS3Operation::HeadObject);
        assert!(route.remote_gateway_required);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::ReturnMetadataOnly)
        );
        assert!(
            !route
                .stages
                .contains(&TrustlessExecutionStage::DecryptObjectLocally)
        );
        assert!(!route.gateway_plaintext_access);
    }

    #[test]
    fn list_route_fetches_encrypted_manifest_and_lists_metadata_locally() {
        let route = TrustlessLocalOperationRouter::route_request(LocalS3Request {
            operation: LocalS3Operation::ListObjectsV2,
            bucket: "bucket".to_owned(),
            key: None,
            prefix: Some("docs/".to_owned()),
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        })
        .unwrap();

        assert_eq!(route.operation, LocalS3Operation::ListObjectsV2);
        assert!(route.remote_gateway_required);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::ReadEncryptedManifest)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::DecryptManifestLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::ReturnMetadataOnly)
        );
        assert!(!route.gateway_plaintext_access);
    }

    #[test]
    fn delete_route_updates_manifest_locally_and_forwards_ciphertext_only() {
        let route =
            TrustlessLocalOperationRouter::route_request(request(LocalS3Operation::DeleteObject))
                .unwrap();

        assert_eq!(route.operation, LocalS3Operation::DeleteObject);
        assert!(route.remote_gateway_required);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::MutateManifestLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::EncryptManifestLocally)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::SendCiphertextOnlyGatewayRequest)
        );
        assert!(!route.gateway_plaintext_access);
    }

    #[test]
    fn create_trustless_bucket_route_anchors_without_remote_plaintext() {
        let route = TrustlessLocalOperationRouter::route_request(LocalS3Request {
            operation: LocalS3Operation::CreateTrustlessBucket,
            bucket: "bucket".to_owned(),
            key: None,
            prefix: None,
            plaintext_body: None,
            plaintext_body_allowed_locally: false,
        })
        .unwrap();

        assert_eq!(route.operation, LocalS3Operation::CreateTrustlessBucket);
        assert!(!route.remote_gateway_required);
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::CreateTrustlessBucketAnchor)
        );
        assert!(
            route
                .stages
                .contains(&TrustlessExecutionStage::ReturnMetadataOnly)
        );
        assert!(!route.gateway_plaintext_access);
    }

    #[test]
    fn router_rejects_plaintext_outside_put_via_local_surface() {
        let err = TrustlessLocalOperationRouter::route_request(LocalS3Request {
            plaintext_body: Some(b"bad".to_vec()),
            ..request(LocalS3Operation::GetObject)
        })
        .unwrap_err();

        assert_eq!(
            err,
            TrustlessRouterError::LocalS3Surface(LocalS3SurfaceError::UnexpectedPlaintextBody)
        );
    }
}
