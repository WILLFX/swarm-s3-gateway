use thiserror::Error;

use crate::encryption::TrustlessEncryptResult;
use crate::planner::{RemoteGatewayAction, TrustlessRoutePlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextGatewayRequest {
    pub bucket_id_hex: String,
    pub action: RemoteGatewayAction,
    pub ciphertext_payload: Option<Vec<u8>>,
    pub encrypted_manifest_payload: Option<Vec<u8>>,
    pub ciphertext_reference_hex: Option<String>,
    pub expected_manifest_reference_hex: Option<String>,
    pub plaintext_payload_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextGatewayResponse {
    pub action: RemoteGatewayAction,
    pub ciphertext_payload: Option<Vec<u8>>,
    pub encrypted_manifest_payload: Option<Vec<u8>>,
    pub ciphertext_reference_hex: Option<String>,
    pub encrypted_manifest_reference_hex: Option<String>,
    pub metadata_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CiphertextGatewayBoundaryError {
    #[error("bucket id is required")]
    MissingBucketId,

    #[error("bucket id must be a 32-byte hex value")]
    InvalidBucketId,

    #[error("object key is required for object gateway action")]
    MissingObjectKey,

    #[error("ciphertext payload is required for PUT ciphertext object")]
    MissingCiphertextPayload,

    #[error("ciphertext reference is required for object read gateway action")]
    MissingCiphertextReference,

    #[error("expected manifest reference is required for DELETE ciphertext object")]
    MissingExpectedManifestReference,

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
        bucket_id_hex: &str,
        encrypted: TrustlessEncryptResult,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;
        let bucket_id_hex = require_bucket_id_hex(bucket_id_hex)?;

        if encrypted.ciphertext.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingCiphertextPayload);
        }

        if encrypted.gateway_plaintext_access || !encrypted.remote_payload_is_ciphertext_only {
            return Err(CiphertextGatewayBoundaryError::PlaintextPayloadRejected);
        }

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::PutCiphertextObject,
            ciphertext_payload: Some(encrypted.ciphertext),
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            expected_manifest_reference_hex: None,
            plaintext_payload_present: false,
        })
    }

    pub fn get_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
        bucket_id_hex: &str,
        ciphertext_reference_hex: Option<String>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;
        let bucket_id_hex = require_bucket_id_hex(bucket_id_hex)?;
        let ciphertext_reference_hex = require_ciphertext_reference(ciphertext_reference_hex)?;

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::GetCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: Some(ciphertext_reference_hex),
            expected_manifest_reference_hex: None,
            plaintext_payload_present: false,
        })
    }

    pub fn head_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
        bucket_id_hex: &str,
        ciphertext_reference_hex: Option<String>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;
        let bucket_id_hex = require_bucket_id_hex(bucket_id_hex)?;
        let ciphertext_reference_hex = require_ciphertext_reference(ciphertext_reference_hex)?;

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::HeadCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: Some(ciphertext_reference_hex),
            expected_manifest_reference_hex: None,
            plaintext_payload_present: false,
        })
    }

    pub fn list_encrypted_manifest_request(
        route_plan: &TrustlessRoutePlan,
        bucket_id_hex: &str,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        let bucket_id_hex = require_bucket_id_hex(bucket_id_hex)?;

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::ListCiphertextManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            expected_manifest_reference_hex: None,
            plaintext_payload_present: false,
        })
    }

    pub fn put_encrypted_manifest_request(
        bucket_id_hex: impl Into<String>,
        encrypted_manifest_payload: Vec<u8>,
        expected_manifest_reference_hex: Option<String>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        let bucket_id_hex = require_bucket_id_hex(&bucket_id_hex.into())?;

        if encrypted_manifest_payload.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingEncryptedManifestPayload);
        }

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::PutEncryptedManifest,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(encrypted_manifest_payload),
            ciphertext_reference_hex: None,
            expected_manifest_reference_hex,
            plaintext_payload_present: false,
        })
    }

    pub fn delete_ciphertext_request(
        route_plan: &TrustlessRoutePlan,
        bucket_id_hex: &str,
        encrypted_manifest_payload: Vec<u8>,
        expected_manifest_reference_hex: Option<String>,
    ) -> Result<CiphertextGatewayRequest, CiphertextGatewayBoundaryError> {
        validate_route(route_plan)?;
        require_object_key(route_plan)?;
        let bucket_id_hex = require_bucket_id_hex(bucket_id_hex)?;

        if encrypted_manifest_payload.is_empty() {
            return Err(CiphertextGatewayBoundaryError::MissingEncryptedManifestPayload);
        }

        let expected_manifest_reference_hex =
            require_expected_manifest_reference(expected_manifest_reference_hex)?;

        Ok(CiphertextGatewayRequest {
            bucket_id_hex,
            action: RemoteGatewayAction::DeleteCiphertextObject,
            ciphertext_payload: None,
            encrypted_manifest_payload: Some(encrypted_manifest_payload),
            ciphertext_reference_hex: None,
            expected_manifest_reference_hex: Some(expected_manifest_reference_hex),
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

fn require_bucket_id_hex(bucket_id_hex: &str) -> Result<String, CiphertextGatewayBoundaryError> {
    let bucket_id_hex = bucket_id_hex.trim().trim_start_matches("0x").to_owned();

    if bucket_id_hex.is_empty() {
        return Err(CiphertextGatewayBoundaryError::MissingBucketId);
    }

    let Ok(bytes) = hex::decode(&bucket_id_hex) else {
        return Err(CiphertextGatewayBoundaryError::InvalidBucketId);
    };

    if bytes.len() != 32 {
        return Err(CiphertextGatewayBoundaryError::InvalidBucketId);
    }

    Ok(bucket_id_hex)
}

fn require_ciphertext_reference(
    ciphertext_reference_hex: Option<String>,
) -> Result<String, CiphertextGatewayBoundaryError> {
    match ciphertext_reference_hex {
        Some(reference) if !reference.trim().is_empty() => Ok(reference),
        _ => Err(CiphertextGatewayBoundaryError::MissingCiphertextReference),
    }
}

fn require_expected_manifest_reference(
    expected_manifest_reference_hex: Option<String>,
) -> Result<String, CiphertextGatewayBoundaryError> {
    match expected_manifest_reference_hex {
        Some(reference) if !reference.trim().is_empty() => Ok(reference),
        _ => Err(CiphertextGatewayBoundaryError::MissingExpectedManifestReference),
    }
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

    fn bucket_id_hex() -> String {
        hex::encode([1u8; 32])
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

        let request = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            encrypted_result(),
        )
        .unwrap();

        assert_eq!(request.bucket_id_hex, bucket_id_hex());
        assert_eq!(request.action, RemoteGatewayAction::PutCiphertextObject);
        assert_eq!(request.ciphertext_payload, Some(b"ciphertext".to_vec()));
        assert!(request.encrypted_manifest_payload.is_none());
        assert!(request.ciphertext_reference_hex.is_none());
        assert!(request.expected_manifest_reference_hex.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn get_and_head_requests_never_include_plaintext_payloads() {
        let get_plan = make_route_plan(
            TrustlessProxyOperation::GetObject,
            RemoteGatewayAction::GetCiphertextObject,
        );

        let get_request = CiphertextGatewayBoundary::get_ciphertext_request(
            &get_plan,
            &bucket_id_hex(),
            Some("ab".repeat(32)),
        )
        .unwrap();

        assert_eq!(get_request.bucket_id_hex, bucket_id_hex());
        assert_eq!(get_request.action, RemoteGatewayAction::GetCiphertextObject);
        assert!(get_request.ciphertext_payload.is_none());
        assert_eq!(get_request.ciphertext_reference_hex, Some("ab".repeat(32)));
        assert!(get_request.expected_manifest_reference_hex.is_none());
        assert!(!get_request.plaintext_payload_present);

        let head_plan = make_route_plan(
            TrustlessProxyOperation::HeadObject,
            RemoteGatewayAction::HeadCiphertextObject,
        );

        let head_request = CiphertextGatewayBoundary::head_ciphertext_request(
            &head_plan,
            &bucket_id_hex(),
            Some("cd".repeat(32)),
        )
        .unwrap();

        assert_eq!(head_request.bucket_id_hex, bucket_id_hex());
        assert_eq!(
            head_request.action,
            RemoteGatewayAction::HeadCiphertextObject
        );
        assert!(head_request.ciphertext_payload.is_none());
        assert_eq!(head_request.ciphertext_reference_hex, Some("cd".repeat(32)));
        assert!(head_request.expected_manifest_reference_hex.is_none());
        assert!(!head_request.plaintext_payload_present);
    }

    #[test]
    fn get_and_head_requests_require_manifest_ciphertext_reference() {
        let get_plan = make_route_plan(
            TrustlessProxyOperation::GetObject,
            RemoteGatewayAction::GetCiphertextObject,
        );

        let err =
            CiphertextGatewayBoundary::get_ciphertext_request(&get_plan, &bucket_id_hex(), None)
                .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::MissingCiphertextReference
        );

        let head_plan = make_route_plan(
            TrustlessProxyOperation::HeadObject,
            RemoteGatewayAction::HeadCiphertextObject,
        );

        let err = CiphertextGatewayBoundary::head_ciphertext_request(
            &head_plan,
            &bucket_id_hex(),
            Some(" ".to_owned()),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::MissingCiphertextReference
        );
    }

    #[test]
    fn get_and_head_requests_can_forward_manifest_ciphertext_reference() {
        let get_plan = make_route_plan(
            TrustlessProxyOperation::GetObject,
            RemoteGatewayAction::GetCiphertextObject,
        );

        let get_request = CiphertextGatewayBoundary::get_ciphertext_request(
            &get_plan,
            &bucket_id_hex(),
            Some("ab".repeat(32)),
        )
        .unwrap();

        assert_eq!(get_request.ciphertext_reference_hex, Some("ab".repeat(32)));
        assert!(get_request.expected_manifest_reference_hex.is_none());

        let head_plan = make_route_plan(
            TrustlessProxyOperation::HeadObject,
            RemoteGatewayAction::HeadCiphertextObject,
        );

        let head_request = CiphertextGatewayBoundary::head_ciphertext_request(
            &head_plan,
            &bucket_id_hex(),
            Some("cd".repeat(32)),
        )
        .unwrap();

        assert_eq!(head_request.ciphertext_reference_hex, Some("cd".repeat(32)));
        assert!(head_request.expected_manifest_reference_hex.is_none());
    }

    #[test]
    fn list_request_fetches_encrypted_manifest_without_plaintext_payload() {
        let mut route_plan = make_route_plan(
            TrustlessProxyOperation::ListObjectsV2,
            RemoteGatewayAction::ListCiphertextManifest,
        );
        route_plan.key = None;

        let request = CiphertextGatewayBoundary::list_encrypted_manifest_request(
            &route_plan,
            &bucket_id_hex(),
        )
        .unwrap();

        assert_eq!(request.bucket_id_hex, bucket_id_hex());
        assert_eq!(request.action, RemoteGatewayAction::ListCiphertextManifest);
        assert!(request.ciphertext_payload.is_none());
        assert!(request.encrypted_manifest_payload.is_none());
        assert!(request.ciphertext_reference_hex.is_none());
        assert!(request.expected_manifest_reference_hex.is_none());
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn put_encrypted_manifest_request_forwards_only_encrypted_manifest_payload() {
        let request = CiphertextGatewayBoundary::put_encrypted_manifest_request(
            bucket_id_hex(),
            b"encrypted-manifest".to_vec(),
            Some("01".repeat(32)),
        )
        .unwrap();

        assert_eq!(request.bucket_id_hex, bucket_id_hex());
        assert_eq!(request.action, RemoteGatewayAction::PutEncryptedManifest);
        assert_eq!(
            request.encrypted_manifest_payload,
            Some(b"encrypted-manifest".to_vec())
        );
        assert!(request.ciphertext_payload.is_none());
        assert!(request.ciphertext_reference_hex.is_none());
        assert_eq!(
            request.expected_manifest_reference_hex,
            Some("01".repeat(32))
        );
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn delete_request_forwards_only_encrypted_manifest_payload() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::DeleteObject,
            RemoteGatewayAction::DeleteCiphertextObject,
        );

        let request = CiphertextGatewayBoundary::delete_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            b"manifest".to_vec(),
            Some("02".repeat(32)),
        )
        .unwrap();

        assert_eq!(request.bucket_id_hex, bucket_id_hex());
        assert_eq!(request.action, RemoteGatewayAction::DeleteCiphertextObject);
        assert_eq!(
            request.encrypted_manifest_payload,
            Some(b"manifest".to_vec())
        );
        assert!(request.ciphertext_payload.is_none());
        assert!(request.ciphertext_reference_hex.is_none());
        assert_eq!(
            request.expected_manifest_reference_hex,
            Some("02".repeat(32))
        );
        assert!(!request.plaintext_payload_present);
    }

    #[test]
    fn delete_request_requires_expected_manifest_reference() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::DeleteObject,
            RemoteGatewayAction::DeleteCiphertextObject,
        );

        let err = CiphertextGatewayBoundary::delete_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            b"manifest".to_vec(),
            None,
        )
        .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::MissingExpectedManifestReference
        );
    }

    #[test]
    fn boundary_rejects_empty_payloads_for_ciphertext_forwarding() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );

        let err = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
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

        let err = CiphertextGatewayBoundary::delete_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            Vec::new(),
            None,
        )
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

        let err = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            encrypted_result(),
        )
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

        let err = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            &bucket_id_hex(),
            encrypted_result(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CiphertextGatewayBoundaryError::RouteAllowsGatewayPlaintextAccess
        );
    }

    #[test]
    fn boundary_rejects_missing_or_malformed_bucket_id_hex() {
        let route_plan = make_route_plan(
            TrustlessProxyOperation::PutObject,
            RemoteGatewayAction::PutCiphertextObject,
        );

        let err =
            CiphertextGatewayBoundary::put_ciphertext_request(&route_plan, " ", encrypted_result())
                .unwrap_err();
        assert_eq!(err, CiphertextGatewayBoundaryError::MissingBucketId);

        let err = CiphertextGatewayBoundary::put_ciphertext_request(
            &route_plan,
            "not-hex",
            encrypted_result(),
        )
        .unwrap_err();
        assert_eq!(err, CiphertextGatewayBoundaryError::InvalidBucketId);

        let err = CiphertextGatewayBoundary::list_encrypted_manifest_request(
            &route_plan,
            &"01".repeat(8),
        )
        .unwrap_err();
        assert_eq!(err, CiphertextGatewayBoundaryError::InvalidBucketId);
    }

    #[test]
    fn boundary_rejects_responses_that_claim_gateway_plaintext_access() {
        let err = CiphertextGatewayBoundary::validate_response(CiphertextGatewayResponse {
            action: RemoteGatewayAction::GetCiphertextObject,
            ciphertext_payload: Some(b"ciphertext".to_vec()),
            encrypted_manifest_payload: None,
            ciphertext_reference_hex: None,
            encrypted_manifest_reference_hex: None,
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
