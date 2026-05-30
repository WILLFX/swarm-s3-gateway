use thiserror::Error;

use crate::types::{RecipientEnvelopeContext, TrustlessBucketType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustlessProxyOperation {
    PutObject,
    GetObject,
    HeadObject,
    ListObjectsV2,
    DeleteObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTrustlessStep {
    ConfirmTrustlessPrivateBucket,
    LookupRecipientEncryptionKeys,
    EncryptPayloadLocally,
    FetchCiphertextObject,
    DecryptPayloadLocally,
    ReadEncryptedBucketManifest,
    DecryptBucketManifestLocally,
    UpdateBucketManifestLocally,
    EncryptBucketManifestLocally,
    ReturnMetadataOnly,
    ValidateCiphertextOnlyForwarding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteGatewayAction {
    CreateTrustlessBucket,
    PutCiphertextObject,
    GetCiphertextObject,
    HeadCiphertextObject,
    ListCiphertextManifest,
    PutEncryptedManifest,
    DeleteCiphertextObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessRoutePlan {
    pub operation: TrustlessProxyOperation,
    pub bucket_type: TrustlessBucketType,
    pub bucket: String,
    pub key: Option<String>,
    pub local_steps: Vec<LocalTrustlessStep>,
    pub remote_action: RemoteGatewayAction,
    pub ciphertext_only_remote: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlannerError {
    #[error("bucket name is required")]
    MissingBucket,

    #[error("object key is required")]
    MissingObjectKey,

    #[error("recipient envelope context is required for trustless private PUT")]
    MissingRecipientEnvelopeContext,
}

pub struct TrustlessRoutePlanner;

impl TrustlessRoutePlanner {
    pub fn plan_put_object(
        bucket: impl Into<String>,
        key: impl Into<String>,
        envelope_context: Option<&RecipientEnvelopeContext>,
    ) -> Result<TrustlessRoutePlan, PlannerError> {
        let bucket = require_bucket(bucket.into())?;
        let key = require_key(key.into())?;

        if envelope_context.is_none() {
            return Err(PlannerError::MissingRecipientEnvelopeContext);
        }

        Ok(TrustlessRoutePlan {
            operation: TrustlessProxyOperation::PutObject,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket,
            key: Some(key),
            local_steps: vec![
                LocalTrustlessStep::ConfirmTrustlessPrivateBucket,
                LocalTrustlessStep::LookupRecipientEncryptionKeys,
                LocalTrustlessStep::EncryptPayloadLocally,
                LocalTrustlessStep::ReadEncryptedBucketManifest,
                LocalTrustlessStep::DecryptBucketManifestLocally,
                LocalTrustlessStep::UpdateBucketManifestLocally,
                LocalTrustlessStep::EncryptBucketManifestLocally,
                LocalTrustlessStep::ValidateCiphertextOnlyForwarding,
            ],
            remote_action: RemoteGatewayAction::PutCiphertextObject,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn plan_get_object(
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<TrustlessRoutePlan, PlannerError> {
        let bucket = require_bucket(bucket.into())?;
        let key = require_key(key.into())?;

        Ok(TrustlessRoutePlan {
            operation: TrustlessProxyOperation::GetObject,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket,
            key: Some(key),
            local_steps: vec![
                LocalTrustlessStep::ConfirmTrustlessPrivateBucket,
                LocalTrustlessStep::FetchCiphertextObject,
                LocalTrustlessStep::DecryptPayloadLocally,
            ],
            remote_action: RemoteGatewayAction::GetCiphertextObject,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn plan_head_object(
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<TrustlessRoutePlan, PlannerError> {
        let bucket = require_bucket(bucket.into())?;
        let key = require_key(key.into())?;

        Ok(TrustlessRoutePlan {
            operation: TrustlessProxyOperation::HeadObject,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket,
            key: Some(key),
            local_steps: vec![
                LocalTrustlessStep::ConfirmTrustlessPrivateBucket,
                LocalTrustlessStep::ReturnMetadataOnly,
            ],
            remote_action: RemoteGatewayAction::HeadCiphertextObject,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn plan_list_objects_v2(
        bucket: impl Into<String>,
    ) -> Result<TrustlessRoutePlan, PlannerError> {
        let bucket = require_bucket(bucket.into())?;

        Ok(TrustlessRoutePlan {
            operation: TrustlessProxyOperation::ListObjectsV2,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket,
            key: None,
            local_steps: vec![
                LocalTrustlessStep::ConfirmTrustlessPrivateBucket,
                LocalTrustlessStep::ReadEncryptedBucketManifest,
                LocalTrustlessStep::DecryptBucketManifestLocally,
                LocalTrustlessStep::ReturnMetadataOnly,
            ],
            remote_action: RemoteGatewayAction::ListCiphertextManifest,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn plan_delete_object(
        bucket: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<TrustlessRoutePlan, PlannerError> {
        let bucket = require_bucket(bucket.into())?;
        let key = require_key(key.into())?;

        Ok(TrustlessRoutePlan {
            operation: TrustlessProxyOperation::DeleteObject,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket,
            key: Some(key),
            local_steps: vec![
                LocalTrustlessStep::ConfirmTrustlessPrivateBucket,
                LocalTrustlessStep::ReadEncryptedBucketManifest,
                LocalTrustlessStep::DecryptBucketManifestLocally,
                LocalTrustlessStep::UpdateBucketManifestLocally,
                LocalTrustlessStep::EncryptBucketManifestLocally,
                LocalTrustlessStep::ValidateCiphertextOnlyForwarding,
            ],
            remote_action: RemoteGatewayAction::DeleteCiphertextObject,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        })
    }
}

fn require_bucket(bucket: String) -> Result<String, PlannerError> {
    let bucket = bucket.trim().to_owned();

    if bucket.is_empty() {
        return Err(PlannerError::MissingBucket);
    }

    Ok(bucket)
}

fn require_key(key: String) -> Result<String, PlannerError> {
    let key = key.trim().to_owned();

    if key.is_empty() {
        return Err(PlannerError::MissingObjectKey);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RecipientEnvelopeContext;

    fn envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
        }
    }

    #[test]
    fn put_plan_encrypts_locally_and_forwards_ciphertext_only() {
        let context = envelope_context();

        let plan =
            TrustlessRoutePlanner::plan_put_object("bucket", "secret.txt", Some(&context)).unwrap();

        assert_eq!(plan.operation, TrustlessProxyOperation::PutObject);
        assert_eq!(plan.remote_action, RemoteGatewayAction::PutCiphertextObject);
        assert!(plan.ciphertext_only_remote);
        assert!(!plan.gateway_plaintext_access);
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::LookupRecipientEncryptionKeys)
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::EncryptPayloadLocally)
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::ValidateCiphertextOnlyForwarding)
        );
    }

    #[test]
    fn put_plan_requires_recipient_envelope_context() {
        let err = TrustlessRoutePlanner::plan_put_object("bucket", "secret.txt", None).unwrap_err();

        assert_eq!(err, PlannerError::MissingRecipientEnvelopeContext);
    }

    #[test]
    fn get_plan_fetches_ciphertext_and_decrypts_locally() {
        let plan = TrustlessRoutePlanner::plan_get_object("bucket", "secret.txt").unwrap();

        assert_eq!(plan.operation, TrustlessProxyOperation::GetObject);
        assert_eq!(plan.remote_action, RemoteGatewayAction::GetCiphertextObject);
        assert!(plan.ciphertext_only_remote);
        assert!(!plan.gateway_plaintext_access);
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::FetchCiphertextObject)
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::DecryptPayloadLocally)
        );
    }

    #[test]
    fn head_plan_returns_metadata_without_local_decrypt_step() {
        let plan = TrustlessRoutePlanner::plan_head_object("bucket", "secret.txt").unwrap();

        assert_eq!(plan.operation, TrustlessProxyOperation::HeadObject);
        assert_eq!(
            plan.remote_action,
            RemoteGatewayAction::HeadCiphertextObject
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::ReturnMetadataOnly)
        );
        assert!(
            !plan
                .local_steps
                .contains(&LocalTrustlessStep::DecryptPayloadLocally)
        );
    }

    #[test]
    fn list_plan_decrypts_encrypted_manifest_locally() {
        let plan = TrustlessRoutePlanner::plan_list_objects_v2("bucket").unwrap();

        assert_eq!(plan.operation, TrustlessProxyOperation::ListObjectsV2);
        assert_eq!(
            plan.remote_action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::ReadEncryptedBucketManifest)
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::DecryptBucketManifestLocally)
        );
    }

    #[test]
    fn delete_plan_updates_manifest_locally_and_forwards_ciphertext_only() {
        let plan = TrustlessRoutePlanner::plan_delete_object("bucket", "secret.txt").unwrap();

        assert_eq!(plan.operation, TrustlessProxyOperation::DeleteObject);
        assert_eq!(
            plan.remote_action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(plan.ciphertext_only_remote);
        assert!(!plan.gateway_plaintext_access);
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::UpdateBucketManifestLocally)
        );
        assert!(
            plan.local_steps
                .contains(&LocalTrustlessStep::EncryptBucketManifestLocally)
        );
    }

    #[test]
    fn planner_rejects_empty_bucket_or_key() {
        assert_eq!(
            TrustlessRoutePlanner::plan_get_object("", "key").unwrap_err(),
            PlannerError::MissingBucket
        );

        assert_eq!(
            TrustlessRoutePlanner::plan_get_object("bucket", "").unwrap_err(),
            PlannerError::MissingObjectKey
        );
    }
}
