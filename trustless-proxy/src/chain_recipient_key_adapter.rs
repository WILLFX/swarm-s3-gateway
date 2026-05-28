use std::collections::BTreeMap;

use common::types::{ChainEncryptionKeyRecord, SubstrateAddress32};
use thiserror::Error;

use crate::identity_recipient_resolver::{
    IdentityContractEncryptionKeyRecord, IdentityRecipientKeyReader,
    IdentityRecipientKeyResolverError,
};
use crate::types::SubstrateAccountId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecipientAccountMapping {
    pub account: SubstrateAccountId,
    pub owner: SubstrateAddress32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainRecipientKeyAdapterError {
    #[error("recipient account mapping is required")]
    MissingAccountMapping,

    #[error("recipient account is required")]
    MissingAccount,

    #[error("recipient owner mapping is missing for account: {0}")]
    MissingOwnerForAccount(SubstrateAccountId),

    #[error("chain encryption key owner mismatch, expected {expected}, got {actual}")]
    OwnerMismatch { expected: String, actual: String },

    #[error("chain recipient key lookup failed: {0}")]
    Reader(String),
}

pub trait ChainRecipientEncryptionKeyLookup {
    fn get_encryption_key_by_owner(
        &self,
        owner: SubstrateAddress32,
    ) -> Result<Option<ChainEncryptionKeyRecord>, ChainRecipientKeyAdapterError>;
}

#[derive(Debug, Clone)]
pub struct ChainRecipientKeyReader<R> {
    lookup: R,
    account_owners: BTreeMap<SubstrateAccountId, SubstrateAddress32>,
}

impl<R> ChainRecipientKeyReader<R> {
    pub fn new(
        lookup: R,
        mappings: Vec<ChainRecipientAccountMapping>,
    ) -> Result<Self, ChainRecipientKeyAdapterError> {
        if mappings.is_empty() {
            return Err(ChainRecipientKeyAdapterError::MissingAccountMapping);
        }

        let mut account_owners = BTreeMap::new();

        for mapping in mappings {
            let account = normalize_account(mapping.account)?;
            account_owners.insert(account, mapping.owner);
        }

        Ok(Self {
            lookup,
            account_owners,
        })
    }

    pub fn owner_for_account(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<SubstrateAddress32, ChainRecipientKeyAdapterError> {
        let account = normalize_account(account.to_owned())?;

        self.account_owners.get(&account).copied().ok_or(
            ChainRecipientKeyAdapterError::MissingOwnerForAccount(account),
        )
    }

    pub fn mapped_account_count(&self) -> usize {
        self.account_owners.len()
    }
}

impl<R> IdentityRecipientKeyReader for ChainRecipientKeyReader<R>
where
    R: ChainRecipientEncryptionKeyLookup,
{
    fn read_recipient_encryption_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<IdentityContractEncryptionKeyRecord>, IdentityRecipientKeyResolverError>
    {
        let account = account.trim().to_owned();

        if account.is_empty() {
            return Err(IdentityRecipientKeyResolverError::MissingAccount);
        }

        let owner = self
            .owner_for_account(&account)
            .map_err(|error| IdentityRecipientKeyResolverError::Reader(error.to_string()))?;

        let Some(record) = self
            .lookup
            .get_encryption_key_by_owner(owner)
            .map_err(|error| IdentityRecipientKeyResolverError::Reader(error.to_string()))?
        else {
            return Ok(None);
        };

        chain_record_to_identity_record(account, owner, record)
            .map(Some)
            .map_err(|error| IdentityRecipientKeyResolverError::Reader(error.to_string()))
    }
}

pub fn chain_record_to_identity_record(
    account: SubstrateAccountId,
    expected_owner: SubstrateAddress32,
    record: ChainEncryptionKeyRecord,
) -> Result<IdentityContractEncryptionKeyRecord, ChainRecipientKeyAdapterError> {
    let account = normalize_account(account)?;

    if record.owner != expected_owner {
        return Err(ChainRecipientKeyAdapterError::OwnerMismatch {
            expected: hex::encode(expected_owner),
            actual: hex::encode(record.owner),
        });
    }

    Ok(IdentityContractEncryptionKeyRecord {
        account,
        public_key: record.public_key,
        key_type: record.key_type,
        key_version: record.key_version,
        enabled: record.enabled,
        updated_at: record.updated_at,
    })
}

fn normalize_account(
    account: SubstrateAccountId,
) -> Result<SubstrateAccountId, ChainRecipientKeyAdapterError> {
    let account = account.trim().to_owned();

    if account.is_empty() {
        return Err(ChainRecipientKeyAdapterError::MissingAccount);
    }

    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_recipient_resolver::IdentityContractRecipientKeyResolver;
    use crate::recipient_keys::{RecipientEnvelopeBuilder, RecipientKeyError, RecipientKeyRequest};

    #[derive(Debug, Clone, Default)]
    struct MockChainRecipientLookup {
        records: BTreeMap<SubstrateAddress32, ChainEncryptionKeyRecord>,
        fail: bool,
    }

    impl MockChainRecipientLookup {
        fn with_record(mut self, record: ChainEncryptionKeyRecord) -> Self {
            self.records.insert(record.owner, record);
            self
        }

        fn failing() -> Self {
            Self {
                records: BTreeMap::new(),
                fail: true,
            }
        }
    }

    impl ChainRecipientEncryptionKeyLookup for MockChainRecipientLookup {
        fn get_encryption_key_by_owner(
            &self,
            owner: SubstrateAddress32,
        ) -> Result<Option<ChainEncryptionKeyRecord>, ChainRecipientKeyAdapterError> {
            if self.fail {
                return Err(ChainRecipientKeyAdapterError::Reader(
                    "chain registry read failed".to_owned(),
                ));
            }

            Ok(self.records.get(&owner).cloned())
        }
    }

    fn owner(byte: u8) -> SubstrateAddress32 {
        [byte; 32]
    }

    fn chain_record(
        owner: SubstrateAddress32,
        version: u32,
        enabled: bool,
    ) -> ChainEncryptionKeyRecord {
        ChainEncryptionKeyRecord {
            owner,
            public_key: vec![1, 2, 3, version as u8],
            key_type: b"aws-esdk-rust-recipient-key".to_vec(),
            key_version: version,
            enabled,
            updated_at: 100,
        }
    }

    fn mapping(account: &str, owner: SubstrateAddress32) -> ChainRecipientAccountMapping {
        ChainRecipientAccountMapping {
            account: account.to_owned(),
            owner,
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
    fn chain_recipient_key_reader_maps_chain_records_into_identity_resolver() {
        let lookup = MockChainRecipientLookup::default()
            .with_record(chain_record(owner(1), 1, true))
            .with_record(chain_record(owner(2), 2, true));

        let reader = ChainRecipientKeyReader::new(
            lookup,
            vec![mapping("alice", owner(1)), mapping("bob", owner(2))],
        )
        .unwrap();

        let resolver = IdentityContractRecipientKeyResolver::new(reader);
        let context = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap();

        assert_eq!(context.recipients.len(), 2);
        assert_eq!(context.recipients[0].account, "alice");
        assert_eq!(context.recipients[0].public_key, hex::encode([1, 2, 3, 1]));
        assert_eq!(context.recipients[1].account, "bob");
        assert_eq!(context.recipients[1].key_version, 2);
        assert!(context.recipients.iter().all(|recipient| recipient.enabled));
    }

    #[test]
    fn chain_recipient_key_reader_fails_closed_when_account_mapping_missing() {
        let lookup =
            MockChainRecipientLookup::default().with_record(chain_record(owner(1), 1, true));

        let reader =
            ChainRecipientKeyReader::new(lookup, vec![mapping("alice", owner(1))]).unwrap();

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
    fn chain_recipient_key_reader_fails_closed_when_chain_record_missing() {
        let lookup =
            MockChainRecipientLookup::default().with_record(chain_record(owner(1), 1, true));

        let reader = ChainRecipientKeyReader::new(
            lookup,
            vec![mapping("alice", owner(1)), mapping("bob", owner(2))],
        )
        .unwrap();

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
    fn chain_recipient_key_reader_fails_closed_when_chain_record_disabled() {
        let lookup = MockChainRecipientLookup::default()
            .with_record(chain_record(owner(1), 1, true))
            .with_record(chain_record(owner(2), 1, false));

        let reader = ChainRecipientKeyReader::new(
            lookup,
            vec![mapping("alice", owner(1)), mapping("bob", owner(2))],
        )
        .unwrap();

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
    fn chain_record_to_identity_record_rejects_owner_mismatch() {
        let err = chain_record_to_identity_record(
            "alice".to_owned(),
            owner(1),
            chain_record(owner(2), 1, true),
        )
        .unwrap_err();

        assert_eq!(
            err,
            ChainRecipientKeyAdapterError::OwnerMismatch {
                expected: hex::encode(owner(1)),
                actual: hex::encode(owner(2)),
            }
        );
    }

    #[test]
    fn chain_recipient_key_reader_rejects_empty_account_mapping() {
        let err = ChainRecipientKeyReader::new(
            MockChainRecipientLookup::default(),
            vec![mapping(" ", owner(1))],
        )
        .unwrap_err();

        assert_eq!(err, ChainRecipientKeyAdapterError::MissingAccount);
    }

    #[test]
    fn chain_recipient_key_reader_fails_closed_when_lookup_errors() {
        let reader = ChainRecipientKeyReader::new(
            MockChainRecipientLookup::failing(),
            vec![mapping("alice", owner(1))],
        )
        .unwrap();

        let resolver = IdentityContractRecipientKeyResolver::new(reader);
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
