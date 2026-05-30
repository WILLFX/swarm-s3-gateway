use thiserror::Error;

use crate::encryption::TrustlessEncryptResult;
use crate::planner::{RemoteGatewayAction, TrustlessRoutePlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextGatewayRequest {
    pub bucket: String,
    pub key: Option<String>,
    pub action: RemoteGatewayAction,
    pub ciphertext_payload: Option<Vec<u8>>,
    pub encrypted_manifest_payload: Option<Vec<u8>>,
    pub plaintext_payload_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextGatewayResponse {
    pub action: RemoteGatewayAction,
    pub ciphertext_payload: Option<Vec<u8>>,
    pub encrypted_manifest_payload: Option<Vec<u8>>,
    pub metadata_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CiphertextGatewayBoundaryError {
    #[error("bucket name is required")]
    MissingBucket,

    #[error("object key is required for object gateway action")]
    MissingObjectKey,

    #[error("ciphertext payload is required for PUT ciphertext object")]
    MissingCiphertextPayload,

    #[error("encrypted manifest payload is required for manifest gateway action")]
    MissingEncryptedManifestPayload,

    #[error("plaintext payload must never cross the trustless gateway boundary")]
    PlaintextPayloadRejected,

    #[error("route plan does not require ciphertext-only remote forwarding")]
    RouteAllowsNonCiphertextRemotePayload,

    #[error("route plan would allow gateway plaintext access")]
    RouteAllowsGatewayPlaintextAccess,

    #[error("gateway response attempted to expose plaintext access")]
    GatewayPlaintextAccessRejected,
}

pub struct CiphertextGatewayBoundary;

impl CiphertextGatewayBoundary {
    pub fn put_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
        encrypted: TrustlessEncryptResult,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;

        if encrypted.ciphertext.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingCiphertextPayload);
        }

        if encrypted.gateway_plaintext_access || !encrypted.remote_payload_is_ciphertext_only {
            return Err(CiphertextGatewayBoundaryError::PlaintextPayloadRejected);
        }

        Ok(CiphertextGatewayRequest {
            bucket: require_bucket(&route_plan.bucket)?,
            key: route_plan.key.clone(),
            action: RemoteGatewayAction::PutCiphertextObject,
            ciphertext_payload: Some(encrypted.ciphertext),
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        })
    }

    pub fn get_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;

        Ok(CiphertextGatewayRequest {
            bucket: require_bucket(&route_plan.bucket)?,
            key: route_plan.key.clone(),
            action: RemoteGatewayAction::GetCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        })
    }

    pub fn head_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;

        Ok(CiphertextGatewayRequest {
            bucket: require_bucket(&route_plan.bucket)?,
            key: route_plan.key.clone(),
            action: RemoteGatewayAction::HeadCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        })
    }

    pub fn list_encrypted_manifest_request(
        route_plan: &TrustlessRoutePlan,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;

        Ok(CiphertextGatewayRequest {
            bucket: require_bucket(&route_plan.bucket)?,
            key: None,
            action: RemoteGatewayAction::ListCiphertextManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            plaintext_payload_present: false,
        })
    }

    pub fn put_encrypted_manifest_request(
        bucket: impl Into<String>,
        encrypted_manifest_payload: Vec<u8>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        let bucket = require_bucket(&bucket.into())?;

        if encrypted_manifest_payload.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingEncryptedManifestPayload);
        }

        Ok(CiphertextGatewayRequest {
            bucket,
            key: None,
            action: RemoteGatewayAction::PutEncryptedManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(encrypted_manifest_payload),
            plaintext_payload_present: false,
        })
    }

    pub fn delete_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
        encrypted_manifest_payload: Vec<u8>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;

        if encrypted_manifest_payload.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingEncryptedManifestPayload);
        }

        Ok(CiphertextGatewayRequest {
            bucket: require_bucket(&route_plan.bucket)?,
            key: route_plan.key.clone(),
            action: RemoteGatewayAction::DeleteCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(encrypted_manifest_payload),
            plaintext_payload_present: false,
        })
    }

    pub fn validate_response(
        response: CiphertextGatewayResponse,
    ) -> Result<CiphertextGatewayResponse, CiphertextGatewayBoundaryError> {
        if response.gateway_plaintext_access {
            return Err(CiphertextGatewayBoundaryError::GatewayPlaintextAccessRejected);
        }

        Ok(response)
    }
}

fn validate_route(route_plan: &TrustlessRoutePlan) -> Result<(), CiphertextGatewayBoundaryError> {
    if !route_plan.ciphertext_only_remote {
        return Err(CiphertextGatewayBoundaryError::RouteAllowsNonCiphertextRemotePayload);
    }

    if route_plan.gateway_plaintext_access {
        return Err(CiphertextGatewayBoundaryError::RouteAllowsGatewayPlaintextAccess);
    }

    Ok(())
}

fn require_bucket(bucket: &str) -> Result<String, CiphertextGatewayBoundaryError> {
    let bucket = bucket.trim().to_owned();

    if bucket.is_empty() {
        return Err(CiphertextGatewayBoundaryError::MissingBucket);
    }

    Ok(bucket)
}

fn require_object_key(
    route_plan: &TrustlessRoutePlan,
) -> Result<(), CiphertextGatewayBoundaryError> {
    let Some(key) = &route_plan.key else {
        return Err(CiphertextGatewayBoundaryError::MissingObjectKey);
    };

    if key.trim().is_empty() {
        return Err(CiphertextGatewayBoundaryError::MissingObjectKey);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::TrustlessEncryptResult;
    use crate::planner::{TrustlessProxyOperation, TrustlessRoutePlan};
    use crate::types::{RecipientEnvelopeContext, TrustlessBucketType};

    fn envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
        }
    }

    fn make_route_plan(
        operation: TrustlessProxyOperation,
        action: RemoteGatewayAction,
    ) -> TrustlessRoutePlan {
        TrustlessRoutePlan {
            operation,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            local_steps: Vec::new(),
            remote_action: action,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        }
    }

    fn encrypted_result() -> TrustlessEncryptResult {
        TrustlessEncryptResult {
            ciphertext: b"ciphertext".to_vec(),
            envelope_context: envelope_context(),
            remote_payload_is_ciphertext_only: true,
            gateway_plaintext_access: false,
        }
    }

    #[test]
    fn put_request_forwards_ciphertext_only_payload() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );

        let request =
            CiphertextGatewayBoundary::put_ciphertext_request(&route_plan, encrypted_result())
                .unwrap();

        assert_eq!(request.action, RemoteGatewayAction::PutCiphertextObject);
        assert_eq!(request.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(request.encrypted_manifest_payload.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn get_and_head_requests_never_include_plaintext_payloads() {
        let get_plan = make_route_plan(
            TrustlessProxyOperation::GetObject,
            RemoteGatewayAction::GetCiphertextObject,
        );

        let get_request = CiphertextGatewayBoundary::get_ciphertext_request(&get_plan).unwrap();

        assert_eq!(get_request.action, RemoteGatewayAction::GetCiphertextObject);
        assert!(get_request.ciphertext_payload.is_none());
        assert!(!get_request.plaintext_payload_present);

        let head_plan = make_route_plan(
            TrustlessProxyOperation::HeadObject,
            RemoteGatewayAction::HeadCiphertextObject,
        );

        let head_request = CiphertextGatewayBoundary::head_ciphertext_request(&head_plan).unwrap();

        assert_eq!(
            head_request.action,
            RemoteGatewayAction::HeadCiphertextObject
        );
        assert!(head_request.ciphertext_payload.is_none());
        assert!(!head_request.plaintext_payload_present);
    }

    #[test]
    fn list_request_fetches_encrypted_manifest_without_plaintext_payload() {
        let mut route_plan = make_route_plan(
            TrustlessProxyOperation::ListObjectsV2,
            RemoteGatewayAction::ListCiphertextManifest,
        );
        route_plan.key = None;

        let request =
            CiphertextGatewayBoundary::list_encrypted_manifest_request(&route_plan).unwrap();

        assert_eq!(request.action, RemoteGatewayAction::ListCiphertextManifest);
        assert!(request.ciphertext_payload.is_none());
        assert!(request.encrypted_manifest_payload.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn put_encrypted_manifest_request_forwards_only_encrypted_manifest_payload() {
        let request = CiphertextGatewayBoundary::put_encrypted_manifest_request(
            "bucket",
            b"encrypted-manifest".to_vec(),
        )
        .unwrap();

        assert_eq!(request.bucket, "bucket");
        assert_eq!(request.key, None);
        assert_eq!(request.action, RemoteGatewayAction::PutEncryptedManifest);
        assert_eq!(
            request.encrypted_manifest_payload,
            Some(b"encrypted-manifest".to_vec())
        );
        assert!(request.ciphertext_payload.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn delete_request_forwards_only_encrypted_manifest_payload() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::DeleteObject,
            RemoteGatewayAction::DeleteCiphertextObject,
        );

        let request =
            CiphertextGatewayBoundary::delete_ciphertext_request(&route_plan, b"manifest".to_vec())
                .unwrap();

        assert_eq!(request.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert_eq!(
            request.encrypted_manifest_payload,
            Some(b"manifest".to_vec())
        );
        assert!(request.ciphertext_payload.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn boundary_rejects_empty_payloads_for_ciphertext_forwarding() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );

        let err = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            TrustlessEncryptResult {
                ciphertext: Vec::new(),
                ..encrypted_result()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::MissingCiphertextPayload
        );

        let route_plan = make_route_plan(
            TrustlessProxyOperation::DeleteObject,
            RemoteGatewayAction::DeleteCiphertextObject,
        );

        let err = CiphertextGatewayBoundary::delete_ciphertext_request(&route_plan, Vec::new())
            .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::MissingEncryptedManifestPayload
        );
    }

    #[test]
    fn boundary_rejects_routes_that_allow_plaintext_or_non_ciphertext_remote() {
        let mut route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );
        route_plan.ciphertext_only_remote = false;

        let err =
            CiphertextGatewayBoundary::put_ciphertext_request(&route_plan, encrypted_result())
                .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::RouteAllowsNonCiphertextRemotePayload
        );

        let mut route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );
        route_plan.gateway_plaintext_access = true;

        let err =
            CiphertextGatewayBoundary::put_ciphertext_request(&route_plan, encrypted_result())
                .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::RouteAllowsGatewayPlaintextAccess
        );
    }

    #[test]
    fn boundary_rejects_responses_that_claim_gateway_plaintext_access() {
        let err = CiphertextGatewayBoundary::validate_response(CiphertextGatewayResponse {
            action: RemoteGatewayAction::GetCiphertextObject,
            ciphertext_payload: Some(b"ciphertext".to_vec()),
            encrypted_manifest_payload: None,
            metadata_only: false,
            gateway_plaintext_access: true,
        })
        .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::GatewayPlaintextAccessRejected
        );
    }
}
