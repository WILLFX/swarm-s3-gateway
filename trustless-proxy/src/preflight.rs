use thiserror::Error;

use crate::local_keystore::{
    LocalKeyRequest, LocalKeystoreError, LocalKeystoreResolver, LocalPrivateKeySelection,
    LocalPrivateKeySelector,
};
use crate::planner::{LocalTrustlessStep, PlannerError, TrustlessRoutePlan, TrustlessRoutePlanner};
use crate::recipient_keys::{
    RecipientEnvelopeBuilder, RecipientKeyError, RecipientKeyRequest, RecipientKeyResolver,
};
use crate::types::{RecipientEnvelopeContext, SubstrateAccountId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPreflightRequest {
    pub bucket: String,
    pub key: Option<String>,
    pub bucket_id: String,
    pub object_key_id: Option<String>,
    pub policy_version: u32,
    pub local_account: SubstrateAccountId,
    pub local_key_type: String,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPutPreflight {
    pub route_plan: TrustlessRoutePlan,
    pub envelope_context: RecipientEnvelopeContext,
    pub local_private_key: LocalPrivateKeySelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessLocalDecryptPreflight {
    pub route_plan: TrustlessRoutePlan,
    pub local_private_key: LocalPrivateKeySelection,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PreflightError {
    #[error("object key is required")]
    MissingObjectKey,

    #[error("object key id is required")]
    MissingObjectKeyId,

    #[error(transparent)]
    Planner(PlannerError),

    #[error(transparent)]
    RecipientKeys(RecipientKeyError),

    #[error(transparent)]
    LocalKeystore(LocalKeystoreError),
}

impl From<PlannerError> for PreflightError {
    fn from(error: PlannerError) -> Self {
        Self::Planner(error)
    }
}

impl From<RecipientKeyError> for PreflightError {
    fn from(error: RecipientKeyError) -> Self {
        Self::RecipientKeys(error)
    }
}

impl From<LocalKeystoreError> for PreflightError {
    fn from(error: LocalKeystoreError) -> Self {
        Self::LocalKeystore(error)
    }
}

pub struct TrustlessOperationPreflightBuilder<RK, LK> {
    recipient_keys: RecipientEnvelopeBuilder<RK>,
    local_keys: LocalPrivateKeySelector<LK>,
}

impl<RK, LK> TrustlessOperationPreflightBuilder<RK, LK>
where
    RK: RecipientKeyResolver,
    LK: LocalKeystoreResolver,
{
    pub fn new(recipient_key_resolver: RK, local_keystore_resolver: LK) -> Self {
        Self {
            recipient_keys: RecipientEnvelopeBuilder::new(recipient_key_resolver),
            local_keys: LocalPrivateKeySelector::new(local_keystore_resolver),
        }
    }

    pub fn preflight_put_object(
        &self,
        request: TrustlessPreflightRequest,
    ) -> Result<TrustlessPutPreflight, PreflightError> {
        let key = require_key(request.key.clone())?;
        let object_key_id = require_object_key_id(request.object_key_id.clone())?;

        let local_private_key = self.select_local_private_key(&request)?;

        let envelope_context = self.recipient_keys.build_context(RecipientKeyRequest {
            bucket_id: request.bucket_id,
            object_key_id,
            policy_version: request.policy_version,
            recipients: request.recipients,
        })?;

        let route_plan =
            TrustlessRoutePlanner::plan_put_object(request.bucket, key, Some(&envelope_context))?;

        Ok(TrustlessPutPreflight {
            route_plan,
            envelope_context,
            local_private_key,
        })
    }

    pub fn preflight_get_object(
        &self,
        request: TrustlessPreflightRequest,
    ) -> Result<TrustlessLocalDecryptPreflight, PreflightError> {
        let key = require_key(request.key.clone())?;
        let local_private_key = self.select_local_private_key(&request)?;
        let route_plan = TrustlessRoutePlanner::plan_get_object(request.bucket, key)?;

        Ok(TrustlessLocalDecryptPreflight {
            route_plan,
            local_private_key,
        })
    }

    pub fn preflight_list_objects_v2(
        &self,
        request: TrustlessPreflightRequest,
    ) -> Result<TrustlessLocalDecryptPreflight, PreflightError> {
        let local_private_key = self.select_local_private_key(&request)?;
        let route_plan = TrustlessRoutePlanner::plan_list_objects_v2(request.bucket)?;

        Ok(TrustlessLocalDecryptPreflight {
            route_plan,
            local_private_key,
        })
    }

    pub fn preflight_delete_object(
        &self,
        request: TrustlessPreflightRequest,
    ) -> Result<TrustlessLocalDecryptPreflight, PreflightError> {
        let key = require_key(request.key.clone())?;
        let local_private_key = self.select_local_private_key(&request)?;
        let route_plan = TrustlessRoutePlanner::plan_delete_object(request.bucket, key)?;

        Ok(TrustlessLocalDecryptPreflight {
            route_plan,
            local_private_key,
        })
    }

    fn select_local_private_key(
        &self,
        request: &TrustlessPreflightRequest,
    ) -> Result<LocalPrivateKeySelection, PreflightError> {
        Ok(self.local_keys.select_enabled_key(LocalKeyRequest {
            account: request.local_account.clone(),
            key_type: request.local_key_type.clone(),
        })?)
    }
}

fn require_key(key: Option<String>) -> Result<String, PreflightError> {
    let Some(key) = key else {
        return Err(PreflightError::MissingObjectKey);
    };

    let key = key.trim().to_owned();

    if key.is_empty() {
        return Err(PreflightError::MissingObjectKey);
    }

    Ok(key)
}

fn require_object_key_id(object_key_id: Option<String>) -> Result<String, PreflightError> {
    let Some(object_key_id) = object_key_id else {
        return Err(PreflightError::MissingObjectKeyId);
    };

    let object_key_id = object_key_id.trim().to_owned();

    if object_key_id.is_empty() {
        return Err(PreflightError::MissingObjectKeyId);
    }

    Ok(object_key_id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::local_keystore::{LocalKeystoreRecord, LocalKeystoreResolver};
    use crate::planner::{LocalTrustlessStep, RemoteGatewayAction};
    use crate::recipient_keys::{RecipientKeyRecord, RecipientKeyResolver};

    #[derive(Debug, Default)]
    struct MockRecipientKeyResolver {
        records: BTreeMap<SubstrateAccountId, RecipientKeyRecord>,
    }

    impl MockRecipientKeyResolver {
        fn with_record(mut self, record: RecipientKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }
    }

    impl RecipientKeyResolver for MockRecipientKeyResolver {
        fn resolve_recipient_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
            Ok(self.records.get(account).cloned())
        }
    }

    #[derive(Debug, Default)]
    struct MockLocalKeystoreResolver {
        records: BTreeMap<(SubstrateAccountId, String), Vec<LocalKeystoreRecord>>,
    }

    impl MockLocalKeystoreResolver {
        fn with_record(mut self, record: LocalKeystoreRecord) -> Self {
            self.records
                .entry((record.account.clone(), record.key_type.clone()))
                .or_default()
                .push(record);
            self
        }
    }

    impl LocalKeystoreResolver for MockLocalKeystoreResolver {
        fn list_local_private_keys(
            &self,
            account: &SubstrateAccountId,
            key_type: &str,
        ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreError> {
            Ok(self
                .records
                .get(&(account.clone(), key_type.to_owned()))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn request() -> TrustlessPreflightRequest {
        TrustlessPreflightRequest {
            bucket: "private-bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: Some(hex::encode([2u8; 32])),
            policy_version: 1,
            local_account: "alice".to_owned(),
            local_key_type: "aws-esdk-rust-recipient-key".to_owned(),
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    fn recipient_record(account: &str) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: format!("{account}-public-key"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn local_record(version: u32) -> LocalKeystoreRecord {
        LocalKeystoreRecord {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: version,
            encrypted_private_key_blob: vec![1, 2, 3, version as u8],
            enabled: true,
            storage_label: format!("local-keystore/alice/{version}"),
        }
    }

    fn builder()
    -> TrustlessOperationPreflightBuilder<MockRecipientKeyResolver, MockLocalKeystoreResolver> {
        TrustlessOperationPreflightBuilder::new(
            MockRecipientKeyResolver::default()
                .with_record(recipient_record("alice"))
                .with_record(recipient_record("bob")),
            MockLocalKeystoreResolver::default().with_record(local_record(7)),
        )
    }

    #[test]
    fn put_preflight_combines_route_plan_recipient_envelopes_and_local_key() {
        let preflight = builder().preflight_put_object(request()).unwrap();

        assert_eq!(
            preflight.route_plan.remote_action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert!(preflight.route_plan.ciphertext_only_remote);
        assert!(!preflight.route_plan.gateway_plaintext_access);
        assert_eq!(preflight.envelope_context.recipients.len(), 2);
        assert_eq!(preflight.local_private_key.key_version, 7);
        assert!(
            preflight
                .route_plan
                .local_steps
                .contains(&LocalTrustlessStep::EncryptPayloadLocally)
        );
    }

    #[test]
    fn put_preflight_fails_closed_when_recipient_key_is_missing() {
        let preflight_builder = TrustlessOperationPreflightBuilder::new(
            MockRecipientKeyResolver::default().with_record(recipient_record("alice")),
            MockLocalKeystoreResolver::default().with_record(local_record(1)),
        );

        let err = preflight_builder
            .preflight_put_object(request())
            .unwrap_err();

        assert_eq!(
            err,
            PreflightError::RecipientKeys(RecipientKeyError::MissingEnabledRecipientKey(
                "bob".to_owned()
            ))
        );
    }

    #[test]
    fn get_preflight_selects_local_key_and_keeps_gateway_ciphertext_only() {
        let preflight = builder().preflight_get_object(request()).unwrap();

        assert_eq!(
            preflight.route_plan.remote_action,
            RemoteGatewayAction::GetCiphertextObject
        );
        assert!(preflight.route_plan.ciphertext_only_remote);
        assert!(!preflight.route_plan.gateway_plaintext_access);
        assert_eq!(preflight.local_private_key.key_version, 7);
        assert!(
            preflight
                .route_plan
                .local_steps
                .contains(&LocalTrustlessStep::DecryptPayloadLocally)
        );
    }

    #[test]
    fn list_preflight_selects_local_key_for_manifest_decryption() {
        let preflight = builder().preflight_list_objects_v2(request()).unwrap();

        assert_eq!(
            preflight.route_plan.remote_action,
            RemoteGatewayAction::ListCiphertextManifest
        );
        assert_eq!(preflight.local_private_key.key_version, 7);
        assert!(
            preflight
                .route_plan
                .local_steps
                .contains(&LocalTrustlessStep::DecryptBucketManifestLocally)
        );
    }

    #[test]
    fn delete_preflight_selects_local_key_and_updates_manifest_locally() {
        let preflight = builder().preflight_delete_object(request()).unwrap();

        assert_eq!(
            preflight.route_plan.remote_action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert_eq!(preflight.local_private_key.key_version, 7);
        assert!(
            preflight
                .route_plan
                .local_steps
                .contains(&LocalTrustlessStep::UpdateBucketManifestLocally)
        );
    }

    #[test]
    fn preflight_fails_closed_when_local_private_key_is_missing() {
        let preflight_builder = TrustlessOperationPreflightBuilder::new(
            MockRecipientKeyResolver::default()
                .with_record(recipient_record("alice"))
                .with_record(recipient_record("bob")),
            MockLocalKeystoreResolver::default(),
        );

        let err = preflight_builder
            .preflight_get_object(request())
            .unwrap_err();

        assert_eq!(
            err,
            PreflightError::LocalKeystore(LocalKeystoreError::MissingEnabledLocalPrivateKey(
                "alice".to_owned()
            ))
        );
    }

    #[test]
    fn preflight_rejects_missing_object_key_or_object_key_id() {
        assert_eq!(
            builder()
                .preflight_get_object(TrustlessPreflightRequest {
                    key: None,
                    ..request()
                })
                .unwrap_err(),
            PreflightError::MissingObjectKey
        );

        assert_eq!(
            builder()
                .preflight_put_object(TrustlessPreflightRequest {
                    object_key_id: None,
                    ..request()
                })
                .unwrap_err(),
            PreflightError::MissingObjectKeyId
        );
    }
}
