use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext, SubstrateAccountId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkKeyringConfig {
    pub keyring_name: &'static str,
    pub commitment_policy: &'static str,
}

impl Default for AwsEsdkKeyringConfig {
    fn default() -> Self {
        Self {
            keyring_name: "aws-esdk-trustless-recipient-keyring",
            commitment_policy: "require-encrypt-require-decrypt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkRecipientEnvelopeDescriptor {
    pub account: SubstrateAccountId,
    pub public_key: String,
    pub key_type: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEsdkRecipientEnvelopePlan {
    pub bucket_id: String,
    pub object_key_id: String,
    pub policy_version: u32,
    pub recipients: Vec<AwsEsdkRecipientEnvelopeDescriptor>,
    pub uses_official_aws_encryption_sdk: bool,
    pub manual_algorithm_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AwsEsdkTrustlessRecipientKeyring {
    config: AwsEsdkKeyringConfig,
}

impl AwsEsdkTrustlessRecipientKeyring {
    pub fn new(config: AwsEsdkKeyringConfig) -> Self {
        Self { config }
    }

    pub fn recipient_envelope_plan(
        &self,
        context: &RecipientEnvelopeContext,
    ) -> Result<AwsEsdkRecipientEnvelopePlan, KeyringError> {
        let bucket_id = require_non_empty(&context.bucket_id, KeyringError::MissingBucketId)?;
        let object_key_id =
            require_non_empty(&context.object_key_id, KeyringError::MissingObjectKeyId)?;

        if context.recipients.is_empty() {
            return Err(KeyringError::MissingRecipientEnvelopes);
        }

        let mut recipients = Vec::with_capacity(context.recipients.len());

        for recipient in &context.recipients {
            recipients.push(validate_recipient(recipient)?);
        }

        Ok(AwsEsdkRecipientEnvelopePlan {
            bucket_id,
            object_key_id,
            policy_version: context.policy_version,
            recipients,
            uses_official_aws_encryption_sdk: true,
            manual_algorithm_selection: false,
        })
    }

    pub fn commitment_policy(&self) -> &'static str {
        self.config.commitment_policy
    }
}

impl TrustlessRecipientKeyring for AwsEsdkTrustlessRecipientKeyring {
    fn keyring_name(&self) -> &'static str {
        self.config.keyring_name
    }

    fn encrypt_with_recipient_envelopes(
        &self,
        plaintext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        if plaintext.is_empty() {
            return Err(KeyringError::MissingPlaintextPayload);
        }

        self.recipient_envelope_plan(context)?;

        Err(KeyringError::AwsEsdkAdapterNotWired)
    }

    fn decrypt_with_local_recipient_key(
        &self,
        ciphertext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        if ciphertext.is_empty() {
            return Err(KeyringError::MissingCiphertextPayload);
        }

        self.recipient_envelope_plan(context)?;

        Err(KeyringError::AwsEsdkAdapterNotWired)
    }
}

fn validate_recipient(
    recipient: &RecipientEncryptionKey,
) -> Result<AwsEsdkRecipientEnvelopeDescriptor, KeyringError> {
    if !recipient.enabled {
        return Err(KeyringError::DisabledRecipientEnvelope(
            recipient.account.clone(),
        ));
    }

    let public_key = require_non_empty(
        &recipient.public_key,
        KeyringError::EmptyRecipientPublicKey(recipient.account.clone()),
    )?;

    let key_type = require_non_empty(
        &recipient.key_type,
        KeyringError::EmptyRecipientKeyType(recipient.account.clone()),
    )?;

    Ok(AwsEsdkRecipientEnvelopeDescriptor {
        account: recipient.account.clone(),
        public_key,
        key_type,
        key_version: recipient.key_version,
    })
}

fn require_non_empty(value: &str, error: KeyringError) -> Result<String, KeyringError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(account: &str) -> RecipientEncryptionKey {
        RecipientEncryptionKey {
            account: account.to_owned(),
            public_key: format!("{account}-public-key"),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            enabled: true,
        }
    }

    fn context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 7,
            recipients: vec![recipient("alice"), recipient("bob")],
        }
    }

    #[test]
    fn aws_esdk_keyring_builds_recipient_envelope_plan_from_context() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        let plan = keyring.recipient_envelope_plan(&context()).unwrap();

        assert_eq!(
            keyring.keyring_name(),
            "aws-esdk-trustless-recipient-keyring"
        );
        assert_eq!(
            keyring.commitment_policy(),
            "require-encrypt-require-decrypt"
        );
        assert_eq!(plan.policy_version, 7);
        assert_eq!(plan.recipients.len(), 2);
        assert!(plan.uses_official_aws_encryption_sdk);
        assert!(!plan.manual_algorithm_selection);
    }

    #[test]
    fn aws_esdk_keyring_rejects_empty_context_fields() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    bucket_id: " ".to_owned(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingBucketId
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    object_key_id: " ".to_owned(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingObjectKeyId
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_missing_or_disabled_recipients() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: Vec::new(),
                    ..context()
                })
                .unwrap_err(),
            KeyringError::MissingRecipientEnvelopes
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        enabled: false,
                        ..recipient("bob")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::DisabledRecipientEnvelope("bob".to_owned())
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_malformed_recipient_records() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        public_key: " ".to_owned(),
                        ..recipient("alice")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::EmptyRecipientPublicKey("alice".to_owned())
        );

        assert_eq!(
            keyring
                .recipient_envelope_plan(&RecipientEnvelopeContext {
                    recipients: vec![RecipientEncryptionKey {
                        key_type: " ".to_owned(),
                        ..recipient("alice")
                    }],
                    ..context()
                })
                .unwrap_err(),
            KeyringError::EmptyRecipientKeyType("alice".to_owned())
        );
    }

    #[test]
    fn aws_esdk_keyring_fails_closed_until_sdk_wiring_exists() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring.encrypt_with_recipient_envelopes(b"plaintext", &context()),
            Err(KeyringError::AwsEsdkAdapterNotWired)
        );

        assert_eq!(
            keyring.decrypt_with_local_recipient_key(b"ciphertext", &context()),
            Err(KeyringError::AwsEsdkAdapterNotWired)
        );
    }

    #[test]
    fn aws_esdk_keyring_rejects_empty_payloads_before_sdk_wiring() {
        let keyring = AwsEsdkTrustlessRecipientKeyring::default();

        assert_eq!(
            keyring.encrypt_with_recipient_envelopes(b"", &context()),
            Err(KeyringError::MissingPlaintextPayload)
        );

        assert_eq!(
            keyring.decrypt_with_local_recipient_key(b"", &context()),
            Err(KeyringError::MissingCiphertextPayload)
        );
    }
}
