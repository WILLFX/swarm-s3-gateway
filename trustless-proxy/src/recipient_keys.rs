use std::collections::BTreeSet;

use thiserror::Error;

use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext, SubstrateAccountId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyRequest {
    pub bucket_id: String,
    pub object_key_id: String,
    pub policy_version: u32,
    pub recipients: Vec<SubstrateAccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyRecord {
    pub account: SubstrateAccountId,
    pub public_key: String,
    pub key_type: String,
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecipientKeyError {
    #[error("bucket id is required")]
    MissingBucketId,

    #[error("object key id is required")]
    MissingObjectKeyId,

    #[error("at least one recipient is required")]
    MissingRecipients,

    #[error("recipient has no enabled public encryption key: {0}")]
    MissingEnabledRecipientKey(SubstrateAccountId),

    #[error("recipient public encryption key is empty: {0}")]
    EmptyRecipientPublicKey(SubstrateAccountId),

    #[error("recipient key type is empty: {0}")]
    EmptyRecipientKeyType(SubstrateAccountId),
}

pub trait RecipientKeyResolver {
    fn resolve_recipient_key(
        &self,
        account: &SubstrateAccountId,
    ) -> Result<Option<RecipientKeyRecord>, RecipientKeyError>;
}

pub struct RecipientEnvelopeBuilder<R> {
    resolver: R,
}

impl<R> RecipientEnvelopeBuilder<R>
where
    R: RecipientKeyResolver,
{
    pub fn new(resolver: R) -> Self {
        Self { resolver }
    }

    pub fn build_context(
        &self,
        request: RecipientKeyRequest,
    ) -> Result<RecipientEnvelopeContext, RecipientKeyError> {
        let bucket_id = require_non_empty(request.bucket_id, RecipientKeyError::MissingBucketId)?;
        let object_key_id =
            require_non_empty(request.object_key_id, RecipientKeyError::MissingObjectKeyId)?;

        let recipients = normalize_recipients(request.recipients)?;

        let mut recipient_keys = Vec::with_capacity(recipients.len());

        for account in recipients {
            let Some(record) = self.resolver.resolve_recipient_key(&account)? else {
                return Err(RecipientKeyError::MissingEnabledRecipientKey(account));
            };

            if !record.enabled {
                return Err(RecipientKeyError::MissingEnabledRecipientKey(account));
            }

            if record.public_key.trim().is_empty() {
                return Err(RecipientKeyError::EmptyRecipientPublicKey(account));
            }

            if record.key_type.trim().is_empty() {
                return Err(RecipientKeyError::EmptyRecipientKeyType(account));
            }

            recipient_keys.push(RecipientEncryptionKey {
                account: record.account,
                public_key: record.public_key,
                key_type: record.key_type,
                key_version: record.key_version,
                enabled: record.enabled,
            });
        }

        Ok(RecipientEnvelopeContext {
            bucket_id,
            object_key_id,
            policy_version: request.policy_version,
            recipients: recipient_keys,
        })
    }
}

fn require_non_empty(value: String, error: RecipientKeyError) -> Result<String, RecipientKeyError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

fn normalize_recipients(
    recipients: Vec<SubstrateAccountId>,
) -> Result<Vec<SubstrateAccountId>, RecipientKeyError> {
    let mut unique = BTreeSet::new();

    for recipient in recipients {
        let recipient = recipient.trim().to_owned();

        if !recipient.is_empty() {
            unique.insert(recipient);
        }
    }

    if unique.is_empty() {
        return Err(RecipientKeyError::MissingRecipients);
    }

    Ok(unique.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

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

    fn request() -> RecipientKeyRequest {
        RecipientKeyRequest {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: vec!["alice".to_owned(), "bob".to_owned()],
        }
    }

    fn record(account: &str) -> RecipientKeyRecord {
        RecipientKeyRecord {
            account: account.to_owned(),
            public_key: format!("{account}-public-key"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    #[test]
    fn builder_creates_envelope_context_for_enabled_recipient_keys() {
        let resolver = MockRecipientKeyResolver::default()
            .with_record(record("alice"))
            .with_record(record("bob"));

        let context = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap();

        assert_eq!(context.policy_version, 1);
        assert_eq!(context.recipients.len(), 2);
        assert_eq!(context.recipients[0].account, "alice");
        assert_eq!(context.recipients[1].account, "bob");
        assert_eq!(
            context.recipients[0].key_type,
            "aws-esdk-rust-recipient-key"
        );
        assert!(context.recipients.iter().all(|recipient| recipient.enabled));
    }

    #[test]
    fn builder_deduplicates_and_sorts_recipients() {
        let resolver = MockRecipientKeyResolver::default()
            .with_record(record("alice"))
            .with_record(record("bob"));

        let context = RecipientEnvelopeBuilder::new(resolver)
            .build_context(RecipientKeyRequest {
                recipients: vec![
                    " bob ".to_owned(),
                    "alice".to_owned(),
                    "bob".to_owned(),
                    "".to_owned(),
                ],
                ..request()
            })
            .unwrap();

        let accounts = context
            .recipients
            .iter()
            .map(|recipient| recipient.account.as_str())
            .collect::<Vec<_>>();

        assert_eq!(accounts, vec!["alice", "bob"]);
    }

    #[test]
    fn builder_fails_closed_when_recipient_key_is_missing() {
        let resolver = MockRecipientKeyResolver::default().with_record(record("alice"));

        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::MissingEnabledRecipientKey("bob".to_owned())
        );
    }

    #[test]
    fn builder_fails_closed_when_recipient_key_is_disabled() {
        let disabled_bob = RecipientKeyRecord {
            enabled: false,
            ..record("bob")
        };

        let resolver = MockRecipientKeyResolver::default()
            .with_record(record("alice"))
            .with_record(disabled_bob);

        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(request())
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::MissingEnabledRecipientKey("bob".to_owned())
        );
    }

    #[test]
    fn builder_rejects_empty_public_key_or_key_type() {
        let empty_public_key = RecipientKeyRecord {
            public_key: " ".to_owned(),
            ..record("alice")
        };

        let resolver = MockRecipientKeyResolver::default().with_record(empty_public_key);

        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(RecipientKeyRequest {
                recipients: vec!["alice".to_owned()],
                ..request()
            })
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::EmptyRecipientPublicKey("alice".to_owned())
        );

        let empty_key_type = RecipientKeyRecord {
            key_type: " ".to_owned(),
            ..record("alice")
        };

        let resolver = MockRecipientKeyResolver::default().with_record(empty_key_type);

        let err = RecipientEnvelopeBuilder::new(resolver)
            .build_context(RecipientKeyRequest {
                recipients: vec!["alice".to_owned()],
                ..request()
            })
            .unwrap_err();

        assert_eq!(
            err,
            RecipientKeyError::EmptyRecipientKeyType("alice".to_owned())
        );
    }

    #[test]
    fn builder_rejects_missing_bucket_object_or_recipients() {
        let resolver = MockRecipientKeyResolver::default();

        assert_eq!(
            RecipientEnvelopeBuilder::new(resolver)
                .build_context(RecipientKeyRequest {
                    bucket_id: " ".to_owned(),
                    ..request()
                })
                .unwrap_err(),
            RecipientKeyError::MissingBucketId
        );

        let resolver = MockRecipientKeyResolver::default();

        assert_eq!(
            RecipientEnvelopeBuilder::new(resolver)
                .build_context(RecipientKeyRequest {
                    object_key_id: " ".to_owned(),
                    ..request()
                })
                .unwrap_err(),
            RecipientKeyError::MissingObjectKeyId
        );

        let resolver = MockRecipientKeyResolver::default();

        assert_eq!(
            RecipientEnvelopeBuilder::new(resolver)
                .build_context(RecipientKeyRequest {
                    recipients: vec![],
                    ..request()
                })
                .unwrap_err(),
            RecipientKeyError::MissingRecipients
        );
    }
}
