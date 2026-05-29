use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use thiserror::Error;
use zeroize::Zeroize;

use crate::types::SubstrateAccountId;

const LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC: &[u8] = b"S3W-LPK-BLOB-V1";
const LOCAL_PRIVATE_KEY_BLOB_V1_NONCE_LEN: usize = 12;

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

    #[error("local private key encrypted blob format is invalid for account: {0}")]
    InvalidEncryptedPrivateKeyBlobFormat(SubstrateAccountId),

    #[error("local private key encrypted blob decrypt failed for account: {0}")]
    PrivateKeyBlobDecryptFailed(SubstrateAccountId),

    #[error("local private key PEM is invalid for account: {0}")]
    InvalidUnlockedPrivateKeyPem(SubstrateAccountId),
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

pub struct AesGcmLocalPrivateKeyUnlocker {
    unlock_key: [u8; 32],
}

impl AesGcmLocalPrivateKeyUnlocker {
    pub fn new(unlock_key: [u8; 32]) -> Self {
        Self { unlock_key }
    }

    pub fn seal_private_key_for_storage(
        &self,
        selection: &LocalPrivateKeySelection,
        private_key_pem: &[u8],
    ) -> Result<Vec<u8>, LocalKeystoreError> {
        validate_private_key_pem(&selection.account, private_key_pem)?;

        let cipher = Aes256Gcm::new_from_slice(&self.unlock_key).map_err(|_| {
            LocalKeystoreError::PrivateKeyBlobDecryptFailed(selection.account.clone())
        })?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = local_private_key_blob_aad(selection);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: private_key_pem,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                LocalKeystoreError::PrivateKeyBlobDecryptFailed(selection.account.clone())
            })?;

        let mut blob = Vec::with_capacity(
            LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC.len()
                + LOCAL_PRIVATE_KEY_BLOB_V1_NONCE_LEN
                + ciphertext.len(),
        );
        blob.extend_from_slice(LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        Ok(blob)
    }
}

impl fmt::Debug for AesGcmLocalPrivateKeyUnlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmLocalPrivateKeyUnlocker")
            .field("unlock_key", &"<redacted>")
            .finish()
    }
}

impl Drop for AesGcmLocalPrivateKeyUnlocker {
    fn drop(&mut self) {
        self.unlock_key.zeroize();
    }
}

impl LocalPrivateKeyUnlocker for AesGcmLocalPrivateKeyUnlocker {
    fn unlock_private_key(
        &self,
        request: LocalPrivateKeyUnlockRequest,
    ) -> Result<LocalPrivateKeyUnlock, LocalKeystoreError> {
        let selection = request.selection;

        let private_key_pem = decrypt_private_key_blob(&self.unlock_key, &selection)?;
        validate_private_key_pem(&selection.account, &private_key_pem)?;

        Ok(LocalPrivateKeyUnlock {
            account: selection.account,
            key_type: selection.key_type,
            key_version: selection.key_version,
            private_key_pem,
            storage_label: selection.storage_label,
        })
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

fn decrypt_private_key_blob(
    unlock_key: &[u8; 32],
    selection: &LocalPrivateKeySelection,
) -> Result<Vec<u8>, LocalKeystoreError> {
    let blob = &selection.encrypted_private_key_blob;

    if blob.len() <= LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC.len() + LOCAL_PRIVATE_KEY_BLOB_V1_NONCE_LEN
        || !blob.starts_with(LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC)
    {
        return Err(LocalKeystoreError::InvalidEncryptedPrivateKeyBlobFormat(
            selection.account.clone(),
        ));
    }

    let nonce_start = LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC.len();
    let nonce_end = nonce_start + LOCAL_PRIVATE_KEY_BLOB_V1_NONCE_LEN;
    let nonce = Nonce::from_slice(&blob[nonce_start..nonce_end]);
    let ciphertext = &blob[nonce_end..];

    if ciphertext.is_empty() {
        return Err(LocalKeystoreError::InvalidEncryptedPrivateKeyBlobFormat(
            selection.account.clone(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(unlock_key)
        .map_err(|_| LocalKeystoreError::PrivateKeyBlobDecryptFailed(selection.account.clone()))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: local_private_key_blob_aad(selection).as_bytes(),
            },
        )
        .map_err(|_| LocalKeystoreError::PrivateKeyBlobDecryptFailed(selection.account.clone()))
}

fn local_private_key_blob_aad(selection: &LocalPrivateKeySelection) -> String {
    format!(
        "s3w.local-keystore.private-key.v1\naccount={}\nkey_type={}\nkey_version={}\nstorage_label={}",
        selection.account, selection.key_type, selection.key_version, selection.storage_label
    )
}

fn validate_private_key_pem(
    account: &SubstrateAccountId,
    private_key_pem: &[u8],
) -> Result<(), LocalKeystoreError> {
    if private_key_pem.is_empty() {
        return Err(LocalKeystoreError::EmptyUnlockedPrivateKeyPem(
            account.clone(),
        ));
    }

    let pem = std::str::from_utf8(private_key_pem)
        .map_err(|_| LocalKeystoreError::InvalidUnlockedPrivateKeyPem(account.clone()))?;

    if !pem.contains("PRIVATE KEY") {
        return Err(LocalKeystoreError::InvalidUnlockedPrivateKeyPem(
            account.clone(),
        ));
    }

    Ok(())
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

    fn selection_with_blob(blob: Vec<u8>) -> LocalPrivateKeySelection {
        LocalPrivateKeySelection {
            encrypted_private_key_blob: blob,
            ..LocalPrivateKeySelector::new(
                MockLocalKeystoreResolver::default().with_record(record(1)),
            )
            .select_enabled_key(request())
            .unwrap()
        }
    }

    fn private_key_pem() -> Vec<u8> {
        b"-----BEGIN PRIVATE KEY-----\nlocal test key\n-----END PRIVATE KEY-----\n".to_vec()
    }

    #[test]
    fn aes_gcm_unlocker_seals_and_unlocks_private_key_pem_locally() {
        let unlocker = AesGcmLocalPrivateKeyUnlocker::new([7u8; 32]);
        let selection = selection_with_blob(b"placeholder".to_vec());

        let blob = unlocker
            .seal_private_key_for_storage(&selection, &private_key_pem())
            .unwrap();

        assert!(blob.starts_with(LOCAL_PRIVATE_KEY_BLOB_V1_MAGIC));
        assert_ne!(blob, private_key_pem());
        assert!(!String::from_utf8_lossy(&blob).contains("PRIVATE KEY"));

        let unlocked = unlocker
            .unlock_private_key(LocalPrivateKeyUnlockRequest {
                selection: selection_with_blob(blob),
            })
            .unwrap();

        assert_eq!(unlocked.account, "alice");
        assert_eq!(unlocked.key_type, "aws-esdk-rust-recipient-key");
        assert_eq!(unlocked.key_version, 1);
        assert_eq!(unlocked.private_key_pem, private_key_pem());
        assert_eq!(unlocked.storage_label, "local-keystore/alice/1");
    }

    #[test]
    fn aes_gcm_unlocker_rejects_wrong_key_and_tampered_aad() {
        let unlocker = AesGcmLocalPrivateKeyUnlocker::new([7u8; 32]);
        let selection = selection_with_blob(b"placeholder".to_vec());

        let blob = unlocker
            .seal_private_key_for_storage(&selection, &private_key_pem())
            .unwrap();

        let wrong_key = AesGcmLocalPrivateKeyUnlocker::new([8u8; 32]);

        assert_eq!(
            wrong_key
                .unlock_private_key(LocalPrivateKeyUnlockRequest {
                    selection: selection_with_blob(blob.clone()),
                })
                .unwrap_err(),
            LocalKeystoreError::PrivateKeyBlobDecryptFailed("alice".to_owned())
        );

        let mut tampered_selection = selection_with_blob(blob);
        tampered_selection.storage_label = "local-keystore/alice/tampered".to_owned();

        assert_eq!(
            unlocker
                .unlock_private_key(LocalPrivateKeyUnlockRequest {
                    selection: tampered_selection,
                })
                .unwrap_err(),
            LocalKeystoreError::PrivateKeyBlobDecryptFailed("alice".to_owned())
        );
    }

    #[test]
    fn aes_gcm_unlocker_rejects_unversioned_or_non_pem_blobs() {
        let unlocker = AesGcmLocalPrivateKeyUnlocker::new([7u8; 32]);

        assert_eq!(
            unlocker
                .unlock_private_key(LocalPrivateKeyUnlockRequest {
                    selection: selection_with_blob(private_key_pem()),
                })
                .unwrap_err(),
            LocalKeystoreError::InvalidEncryptedPrivateKeyBlobFormat("alice".to_owned())
        );

        let selection = selection_with_blob(b"placeholder".to_vec());
        assert_eq!(
            unlocker
                .seal_private_key_for_storage(&selection, b"not-pem")
                .unwrap_err(),
            LocalKeystoreError::InvalidUnlockedPrivateKeyPem("alice".to_owned())
        );
    }

    #[test]
    fn aes_gcm_unlocker_debug_redacts_unlock_key() {
        let unlocker = AesGcmLocalPrivateKeyUnlocker::new([7u8; 32]);
        let debug = format!("{unlocker:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7, 7"));
    }
}
