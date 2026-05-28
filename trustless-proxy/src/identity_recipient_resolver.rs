use thiserror::Error;

use crate::recipient_keys::{RecipientKeyError, RecipientKeyRecord, RecipientKeyResolver};
use crate::types::SubstrateAccountId;

const DEFAULT_REQUIRED_KEY_TYPE: &str = "aws-esdk-rust-recipient-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityContractEncryptionKeyRecord {
    pub account: SubstrateAccountId,
    pub public_key: Vec<u8>,
    pub key_type: Vec<u8>,
    pub key_version: u32,
    pub enabled: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRecipientKeyResolverConfig {
    pub required_key_type: String,
    pub min_key_version: u32,
    pub require_enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityRecipientKeyResolverError {
    #[error("recipient account is required")]
    MissingAccount,

    #[error("identity contract recipient key was not found: {0}")]
    MissingRecipientKey(SubstrateAccountId),

    #[error("identity contract recipient key account mismatch, expected {expected}, got {actual}")]
    AccountMismatch {
        expected: SubstrateAccountId,
        actual: SubstrateAccountId,
    },

    #[error("identity contract recipient key is disabled: {0}")]
    DisabledRecipientKey(SubstrateAccountId),

    #[error("identity contract recipient public key is empty: {0}")]
    EmptyPublicKey(SubstrateAccountId),

    #[error("identity contract recipient key type is empty: {0}")]
    EmptyKeyType(SubstrateAccountId),

    #[error("identity contract recipient key type is invalid UTF-8: {0}")]
    InvalidKeyTypeUtf8(SubstrateAccountId),

    #[error(
        "identity contract recipient key type mismatch for {account}: expected {expected}, got {actual}"
    )]
    KeyTypeMismatch {
        account: SubstrateAccountId,
        expected: String,
        actual: String,
    },

    #[error(
        "identity contract recipient key version is too old for {account}: required at least {required}, got {actual}"
    )]
    StaleKeyVersion {
        account: SubstrateAccountId,
        required: u32,
        actual: u32,
    },

    #[error("identity recipient key reader failed: {0}")]
    Reader(String),
}

pub trait IdentityRecipientKeyReader {
    fn read_recipient_encryption_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<IdentityContractEncryptionKeyRecord>, IdentityRecipientKeyResolverError>;
}

#[derive(Debug, Clone)]
pub struct IdentityContractRecipientKeyResolver<R> {
    reader: R,
    config: IdentityRecipientKeyResolverConfig,
}

impl Default for IdentityRecipientKeyResolverConfig {
    fn default() -> Self {
        Self {
            required_key_type: DEFAULT_REQUIRED_KEY_TYPE.to_owned(),
            min_key_version: 1,
            require_enabled: true,
        }
    }
}

impl<R> IdentityContractRecipientKeyResolver<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            config: IdentityRecipientKeyResolverConfig::default(),
        }
    }

    pub fn with_config(reader: R, config: IdentityRecipientKeyResolverConfig) -> Self {
        Self { reader, config }
    }

    pub fn config(&self) -> &IdentityRecipientKeyResolverConfig {
        &self.config
    }
}

impl<R> RecipientKeyResolver for IdentityContractRecipientKeyResolver<R>
where
    R: IdentityRecipientKeyReader,
{
    fn resolve_recipient_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError> {
        let account = normalize_account(account)?;

        let Some(record) = self
            .reader
            .read_recipient_encryption_key(&account)
            .map_err(|error| map_identity_error_for_account(error, &account))?
        else {
            return Ok(None);
        };

        let recipient_key = identity_record_to_recipient_key_record(&account, record, &self.config)
            .map_err(map_identity_error)?;

        Ok(Some(recipient_key))
    }
}

pub fn identity_record_to_recipient_key_record(
    expected_account: &SubstrateAccountId,
    record: IdentityContractEncryptionKeyRecord,
    config: &IdentityRecipientKeyResolverConfig,
) -> Result<RecipientKeyRecord, IdentityRecipientKeyResolverError> {
    let expected_account = require_non_empty_account(expected_account)?;
    let actual_account = require_non_empty_account(&record.account)?;

    if actual_account != expected_account {
        return Err(IdentityRecipientKeyResolverError::AccountMismatch {
            expected: expected_account,
            actual: actual_account,
        });
    }

    if config.require_enabled && !record.enabled {
        return Err(IdentityRecipientKeyResolverError::DisabledRecipientKey(
            expected_account,
        ));
    }

    if record.public_key.is_empty() {
        return Err(IdentityRecipientKeyResolverError::EmptyPublicKey(
            expected_account,
        ));
    }

    if record.key_type.is_empty() {
        return Err(IdentityRecipientKeyResolverError::EmptyKeyType(
            expected_account,
        ));
    }

    let key_type = String::from_utf8(record.key_type)
        .map_err(|_| {
            IdentityRecipientKeyResolverError::InvalidKeyTypeUtf8(expected_account.clone())
        })?
        .trim()
        .to_owned();

    if key_type.is_empty() {
        return Err(IdentityRecipientKeyResolverError::EmptyKeyType(
            expected_account,
        ));
    }

    let required_key_type = config.required_key_type.trim().to_owned();

    if !required_key_type.is_empty() && key_type != required_key_type {
        return Err(IdentityRecipientKeyResolverError::KeyTypeMismatch {
            account: expected_account,
            expected: required_key_type,
            actual: key_type,
        });
    }

    if record.key_version < config.min_key_version {
        return Err(IdentityRecipientKeyResolverError::StaleKeyVersion {
            account: expected_account,
            required: config.min_key_version,
            actual: record.key_version,
        });
    }

    Ok(RecipientKeyRecord {
        account: actual_account,
        public_key: hex::encode(record.public_key),
        key_type,
        key_version: record.key_version,
        enabled: record.enabled,
    })
}

fn normalize_account(
    account: &SubstrateAccountId,
) -> Result<SubstrateAccountId, RecipientKeyError> {
    let account = account.trim().to_owned();

    if account.is_empty() {
        return Err(RecipientKeyError::MissingEnabledRecipientKey(account));
    }

    Ok(account)
}

fn require_non_empty_account(
    account: &SubstrateAccountId,
) -> Result<SubstrateAccountId, IdentityRecipientKeyResolverError> {
    let account = account.trim().to_owned();

    if account.is_empty() {
        return Err(IdentityRecipientKeyResolverError::MissingAccount);
    }

    Ok(account)
}

fn map_identity_error_for_account(
    error: IdentityRecipientKeyResolverError,
    requested_account: &SubstrateAccountId,
) -> RecipientKeyError {
    match error {
        IdentityRecipientKeyResolverError::Reader(_)
        | IdentityRecipientKeyResolverError::MissingAccount => {
            RecipientKeyError::MissingEnabledRecipientKey(requested_account.to_owned())
        }
        other => map_identity_error(other),
    }
}

fn map_identity_error(error: IdentityRecipientKeyResolverError) -> RecipientKeyError {
    match error {
        IdentityRecipientKeyResolverError::MissingRecipientKey(account)
        | IdentityRecipientKeyResolverError::DisabledRecipientKey(account) => {
            RecipientKeyError::MissingEnabledRecipientKey(account)
        }
        IdentityRecipientKeyResolverError::MissingAccount => {
            RecipientKeyError::MissingEnabledRecipientKey(String::new())
        }
        IdentityRecipientKeyResolverError::EmptyPublicKey(account) => {
            RecipientKeyError::EmptyRecipientPublicKey(account)
        }
        IdentityRecipientKeyResolverError::EmptyKeyType(account)
        | IdentityRecipientKeyResolverError::InvalidKeyTypeUtf8(account)
        | IdentityRecipientKeyResolverError::KeyTypeMismatch { account, .. } => {
            RecipientKeyError::EmptyRecipientKeyType(account)
        }
        IdentityRecipientKeyResolverError::AccountMismatch { expected, .. } => {
            RecipientKeyError::MissingEnabledRecipientKey(expected)
        }
        IdentityRecipientKeyResolverError::StaleKeyVersion { account, .. } => {
            RecipientKeyError::MissingEnabledRecipientKey(account)
        }
        IdentityRecipientKeyResolverError::Reader(_) => {
            RecipientKeyError::MissingEnabledRecipientKey(String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::recipient_keys::{RecipientEnvelopeBuilder, RecipientKeyRequest};

    #[derive(Debug, Default)]
    struct MockIdentityRecipientKeyReader {
        records: BTreeMap<SubstrateAccountId, IdentityContractEncryptionKeyRecord>,
        fail: bool,
    }

    impl MockIdentityRecipientKeyReader {
        fn with_record(mut self, record: IdentityContractEncryptionKeyRecord) -> Self {
            self.records.insert(record.account.clone(), record);
            self
        }

        fn failing() -> Self {
            Self {
                records: BTreeMap::new(),
                fail: true,
            }
        }
    }

    impl IdentityRecipientKeyReader for MockIdentityRecipientKeyReader {
        fn read_recipient_encryption_key(
            &self,
            account: &SubstrateAccountId,
        ) -> Result<Option<IdentityContractEncryptionKeyRecord>, IdentityRecipientKeyResolverError>
        {
            if self.fail {
                return Err(IdentityRecipientKeyResolverError::Reader(
                    "chain read failed".to_owned(),
                ));
            }

            Ok(self.records.get(account).cloned())
        }
    }

    fn identity_record(
        account: &str,
        version: u32,
        enabled: bool,
    ) -> IdentityContractEncryptionKeyRecord {
        IdentityContractEncryptionKeyRecord {
            account: account.to_owned(),
            public_key: vec![1, 2, 3, version as u8],
            key_type: b"aws-esdk-rust-recipient-key".to_vec(),
            key_version: version,
            enabled,
            updated_at: 100,
        }
    }

    fn request() -> RecipientKeyRequest {
        RecipientKeyRequest {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    #[test]
    fn identity_recipient_resolver_maps_enabled_contract_reads_to_recipient_records() {
        let reader = MockIdentityRecipientKeyReader::default()
            .with_record(identity_record("alice", 1, true))
            .with_record(identity_record("bob", 2, true));

        let resolver = IdentityContractRecipientKeyResolver::new(reader);
        let context = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap();

        assert_eq!(context.recipients.len(), 2);
        assert_eq!(context.recipients[0].account, "alice");
        assert_eq!(context.recipients[0].public_key, hex::encode([1, 2, 3, 1]));
        assert_eq!(
            context.recipients[0].key_type,
            "aws-esdk-rust-recipient-key"
        );
        assert_eq!(context.recipients[1].key_version, 2);
        assert!(context.recipients.iter().all(|recipient| recipient.enabled));
    }

    #[test]
    fn identity_recipient_resolver_fails_closed_when_contract_record_missing() {
        let reader = MockIdentityRecipientKeyReader::default()
            .with_record(identity_record("alice", 1, true));

        let resolver = IdentityContractRecipientKeyResolver::new(reader);
        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::MissingEnabledRecipientKey("bob".to_owned())
        );
    }

    #[test]
    fn identity_recipient_resolver_fails_closed_when_contract_record_disabled() {
        let reader = MockIdentityRecipientKeyReader::default()
            .with_record(identity_record("alice", 1, true))
            .with_record(identity_record("bob", 1, false));

        let resolver = IdentityContractRecipientKeyResolver::new(reader);
        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::MissingEnabledRecipientKey("bob".to_owned())
        );
    }

    #[test]
    fn identity_record_conversion_rejects_wrong_account() {
        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            identity_record("bob", 1, true),
            &IdentityRecipientKeyResolverConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::AccountMismatch {
                expected: "alice".to_owned(),
                actual: "bob".to_owned(),
            }
        );
    }

    #[test]
    fn identity_record_conversion_rejects_empty_public_key_or_key_type() {
        let mut record = identity_record("alice", 1, true);
        record.public_key = Vec::new();

        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            record,
            &IdentityRecipientKeyResolverConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::EmptyPublicKey("alice".to_owned())
        );

        let mut record = identity_record("alice", 1, true);
        record.key_type = Vec::new();

        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            record,
            &IdentityRecipientKeyResolverConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::EmptyKeyType("alice".to_owned())
        );
    }

    #[test]
    fn identity_record_conversion_rejects_invalid_utf8_key_type() {
        let mut record = identity_record("alice", 1, true);
        record.key_type = vec![0xff, 0xfe];

        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            record,
            &IdentityRecipientKeyResolverConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::InvalidKeyTypeUtf8("alice".to_owned())
        );
    }

    #[test]
    fn identity_record_conversion_rejects_wrong_key_type() {
        let mut record = identity_record("alice", 1, true);
        record.key_type = b"wrong-key-type".to_vec();

        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            record,
            &IdentityRecipientKeyResolverConfig::default(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::KeyTypeMismatch {
                account: "alice".to_owned(),
                expected: "aws-esdk-rust-recipient-key".to_owned(),
                actual: "wrong-key-type".to_owned(),
            }
        );
    }

    #[test]
    fn identity_record_conversion_rejects_stale_key_version() {
        let config = IdentityRecipientKeyResolverConfig {
            min_key_version: 3,
            ..IdentityRecipientKeyResolverConfig::default()
        };

        let err = identity_record_to_recipient_key_record(
            &"alice".to_owned(),
            identity_record("alice", 2, true),
            &config,
        )
        .unwrap_err();

        assert_eq!(
            err,
            IdentityRecipientKeyResolverError::StaleKeyVersion {
                account: "alice".to_owned(),
                required: 3,
                actual: 2,
            }
        );
    }

    #[test]
    fn identity_recipient_resolver_fails_closed_when_reader_fails() {
        let resolver =
            IdentityContractRecipientKeyResolver::new(MockIdentityRecipientKeyReader::failing());

        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(RecipientKeyRequest {
                recipients: vec!["alice".to_owned()],
                ..request()
            })
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::MissingEnabledRecipientKey("alice".to_owned())
        );
    }
}
