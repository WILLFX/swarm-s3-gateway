use thiserror::Error;

use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyRequest {
    pub account: SubstrateAccountId,
    pub key_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeystoreRecord {
    pub account: SubstrateAccountId,
    pub key_type: String,
    pub key_version: u32,
    pub encrypted_private_key_blob: Vec<u8>,
    pub enabled: bool,
    pub storage_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrivateKeySelection {
    pub account: SubstrateAccountId,
    pub key_type: String,
    pub key_version: u32,
    pub encrypted_private_key_blob: Vec<u8>,
    pub storage_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrivateKeyUnlockRequest {
    pub selection: LocalPrivateKeySelection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPrivateKeyUnlock {
    pub account: SubstrateAccountId,
    pub key_type: String,
    pub key_version: u32,
    pub private_key_pem: Vec<u8>,
    pub storage_label: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalKeystoreError {
    #[error("local account is required")]
    MissingAccount,

    #[error("local key type is required")]
    MissingKeyType,

    #[error("local account has no enabled private encryption key: {0}")]
    MissingEnabledLocalPrivateKey(SubstrateAccountId),

    #[error("local encrypted private key blob is empty: {0}")]
    EmptyEncryptedPrivateKeyBlob(SubstrateAccountId),

    #[error("local private key storage label is empty: {0}")]
    EmptyStorageLabel(SubstrateAccountId),

    #[error("local private key unlocker is not implemented")]
    UnlockNotImplemented,

    #[error("local private key unlock returned empty PEM for account: {0}")]
    EmptyUnlockedPrivateKeyPem(SubstrateAccountId),

    #[error("local private key unlock account mismatch, expected {expected}, got {actual}")]
    UnlockedPrivateKeyAccountMismatch {
        expected: SubstrateAccountId,
        actual: SubstrateAccountId,
    },

    #[error("local private key unlock key type mismatch, expected {expected}, got {actual}")]
    UnlockedPrivateKeyTypeMismatch { expected: String, actual: String },

    #[error("local private key unlock key version mismatch, expected {expected}, got {actual}")]
    UnlockedPrivateKeyVersionMismatch { expected: u32, actual: u32 },

    #[error("local private key unlock storage label mismatch, expected {expected}, got {actual}")]
    UnlockedPrivateKeyStorageLabelMismatch { expected: String, actual: String },
}

pub trait LocalKeystoreResolver {
    fn list_local_private_keys(
        &self,
        account: &SubstrateAccountId,
        key_type: &str,
    ) -> Result<Vec<LocalKeystoreRecord>, LocalKeystoreError>;
}

pub trait LocalPrivateKeyUnlocker {
    fn unlock_private_key(
        &self,
        request: LocalPrivateKeyUnlockRequest,
    ) -> Result<LocalPrivateKeyUnlock, LocalKeystoreError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedLocalPrivateKeyUnlocker;

impl LocalPrivateKeyUnlocker for FailClosedLocalPrivateKeyUnlocker {
    fn unlock_private_key(
        &self,
        _request: LocalPrivateKeyUnlockRequest,
    ) -> Result<LocalPrivateKeyUnlock, LocalKeystoreError> {
        Err(LocalKeystoreError::UnlockNotImplemented)
    }
}

pub struct LocalPrivateKeySelector<R> {
    resolver: R,
}

impl<R> LocalPrivateKeySelector<R>
where
    R: LocalKeystoreResolver,
{
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub fn select_enabled_key(
        &self,
        request: LocalKeyRequest,
    ) -> Result<LocalPrivateKeySelection, LocalKeystoreError> {
        let account = require_non_empty(request.account, LocalKeystoreError::MissingAccount)?;
        let key_type = require_non_empty(request.key_type, LocalKeystoreError::MissingKeyType)?;

        let mut records = self.resolver.list_local_private_keys(&account, &key_type)?;

        records.retain(|record| record.enabled);
        records.sort_by(|left, right| right.key_version.cmp(&left.key_version));

        let Some(record) = records.into_iter().next() else {
            return Err(LocalKeystoreError::MissingEnabledLocalPrivateKey(account));
        };

        if record.encrypted_private_key_blob.is_empty() {
            return Err(LocalKeystoreError::EmptyEncryptedPrivateKeyBlob(
                record.account,
            ));
        }

        if record.storage_label.trim().is_empty() {
            return Err(LocalKeystoreError::EmptyStorageLabel(record.account));
        }

        Ok(LocalPrivateKeySelection {
            account: record.account,
            key_type: record.key_type,
            key_version: record.key_version,
            encrypted_private_key_blob: record.encrypted_private_key_blob,
            storage_label: record.storage_label,
        })
    }
}

pub fn validate_local_private_key_unlock(
    selection: &LocalPrivateKeySelection,
    unlocked: LocalPrivateKeyUnlock,
) -> Result<LocalPrivateKeyUnlock, LocalKeystoreError> {
    if unlocked.account != selection.account {
        return Err(LocalKeystoreError::UnlockedPrivateKeyAccountMismatch {
            expected: selection.account.clone(),
            actual: unlocked.account,
        });
    }

    if unlocked.key_type != selection.key_type {
        return Err(LocalKeystoreError::UnlockedPrivateKeyTypeMismatch {
            expected: selection.key_type.clone(),
            actual: unlocked.key_type,
        });
    }

    if unlocked.key_version != selection.key_version {
        return Err(LocalKeystoreError::UnlockedPrivateKeyVersionMismatch {
            expected: selection.key_version,
            actual: unlocked.key_version,
        });
    }

    if unlocked.storage_label != selection.storage_label {
        return Err(LocalKeystoreError::UnlockedPrivateKeyStorageLabelMismatch {
            expected: selection.storage_label.clone(),
            actual: unlocked.storage_label,
        });
    }

    if unlocked.private_key_pem.is_empty() {
        return Err(LocalKeystoreError::EmptyUnlockedPrivateKeyPem(
            selection.account.clone(),
        ));
    }

    Ok(unlocked)
}

fn require_non_empty(
    value: String,
    error: LocalKeystoreError,
) -> Result<String, LocalKeystoreError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

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

    fn request() -> LocalKeyRequest {
        LocalKeyRequest {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
        }
    }

    fn record(version: u32) -> LocalKeystoreRecord {
        LocalKeystoreRecord {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: version,
            encrypted_private_key_blob: vec![1, 2, 3, version as u8],
            enabled: true,
            storage_label: format!("local-keystore/alice/{version}"),
        }
    }

    #[test]
    fn selector_picks_highest_enabled_local_private_key_version() {
        let resolver = MockLocalKeystoreResolver::default()
            .with_record(record(1))
            .with_record(record(3))
            .with_record(LocalKeystoreRecord {
                enabled: false,
                ..record(9)
            });

        let selection = LocalPrivateKeySelector::new(resolver)
            .select_enabled_key(request())
            .unwrap();

        assert_eq!(selection.account, "alice");
        assert_eq!(selection.key_type, "aws-esdk-rust-recipient-key");
        assert_eq!(selection.key_version, 3);
        assert_eq!(selection.encrypted_private_key_blob, vec![1, 2, 3, 3]);
        assert_eq!(selection.storage_label, "local-keystore/alice/3");
    }

    #[test]
    fn selector_fails_closed_when_no_enabled_key_exists() {
        let resolver = MockLocalKeystoreResolver::default().with_record(LocalKeystoreRecord {
            enabled: false,
            ..record(1)
        });

        let err = LocalPrivateKeySelector::new(resolver)
            .select_enabled_key(request())
            .unwrap_err();

        assert_eq!(
            err,
            LocalKeystoreError::MissingEnabledLocalPrivateKey("alice".to_owned())
        );
    }

    #[test]
    fn selector_rejects_empty_encrypted_private_key_blob() {
        let resolver = MockLocalKeystoreResolver::default().with_record(LocalKeystoreRecord {
            encrypted_private_key_blob: Vec::new(),
            ..record(1)
        });

        let err = LocalPrivateKeySelector::new(resolver)
            .select_enabled_key(request())
            .unwrap_err();

        assert_eq!(
            err,
            LocalKeystoreError::EmptyEncryptedPrivateKeyBlob("alice".to_owned())
        );
    }

    #[test]
    fn selector_rejects_empty_storage_label() {
        let resolver = MockLocalKeystoreResolver::default().with_record(LocalKeystoreRecord {
            storage_label: " ".to_owned(),
            ..record(1)
        });

        let err = LocalPrivateKeySelector::new(resolver)
            .select_enabled_key(request())
            .unwrap_err();

        assert_eq!(
            err,
            LocalKeystoreError::EmptyStorageLabel("alice".to_owned())
        );
    }

    #[test]
    fn selector_rejects_missing_account_or_key_type() {
        let resolver = MockLocalKeystoreResolver::default();

        assert_eq!(
            LocalPrivateKeySelector::new(resolver)
                .select_enabled_key(LocalKeyRequest {
                    account: " ".to_owned(),
                    ..request()
                })
                .unwrap_err(),
            LocalKeystoreError::MissingAccount
        );

        let resolver = MockLocalKeystoreResolver::default();

        assert_eq!(
            LocalPrivateKeySelector::new(resolver)
                .select_enabled_key(LocalKeyRequest {
                    key_type: " ".to_owned(),
                    ..request()
                })
                .unwrap_err(),
            LocalKeystoreError::MissingKeyType
        );
    }

    #[test]
    fn selection_exposes_only_encrypted_private_key_blob_not_plaintext_key() {
        let resolver = MockLocalKeystoreResolver::default().with_record(record(1));

        let selection = LocalPrivateKeySelector::new(resolver)
            .select_enabled_key(request())
            .unwrap();

        assert_eq!(selection.encrypted_private_key_blob, vec![1, 2, 3, 1]);
        assert_eq!(selection.storage_label, "local-keystore/alice/1");
    }

    #[test]
    fn fail_closed_unlocker_rejects_before_private_key_exposure() {
        let request = LocalPrivateKeyUnlockRequest {
            selection: LocalPrivateKeySelector::new(
                MockLocalKeystoreResolver::default().with_record(record(1)),
            )
            .select_enabled_key(request())
            .unwrap(),
        };

        assert_eq!(
            FailClosedLocalPrivateKeyUnlocker.unlock_private_key(request),
            Err(LocalKeystoreError::UnlockNotImplemented)
        );
    }

    #[test]
    fn unlock_validation_rejects_mismatched_or_empty_plaintext_pem() {
        let selection = LocalPrivateKeySelector::new(
            MockLocalKeystoreResolver::default().with_record(record(1)),
        )
        .select_enabled_key(request())
        .unwrap();

        assert_eq!(
            validate_local_private_key_unlock(
                &selection,
                LocalPrivateKeyUnlock {
                    account: "mallory".to_owned(),
                    key_type: selection.key_type.clone(),
                    key_version: selection.key_version,
                    private_key_pem: b"pem".to_vec(),
                    storage_label: selection.storage_label.clone(),
                },
            ),
            Err(LocalKeystoreError::UnlockedPrivateKeyAccountMismatch {
                expected: "alice".to_owned(),
                actual: "mallory".to_owned(),
            })
        );

        assert_eq!(
            validate_local_private_key_unlock(
                &selection,
                LocalPrivateKeyUnlock {
                    account: selection.account.clone(),
                    key_type: selection.key_type.clone(),
                    key_version: selection.key_version,
                    private_key_pem: Vec::new(),
                    storage_label: selection.storage_label.clone(),
                },
            ),
            Err(LocalKeystoreError::EmptyUnlockedPrivateKeyPem(
                "alice".to_owned()
            ))
        );
    }
}
