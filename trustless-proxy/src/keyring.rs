use thiserror::Error;

use crate::types::RecipientEnvelopeContext;

/// Boundary for the future AWS Encryption SDK for Rust custom keyring.
///
/// The implementation must wrap AWS Encryption SDK data keys to recipient public
/// encryption keys fetched from the identity contract. It must never send
/// plaintext object bytes, plaintext data keys, or the local private encryption
/// key to the remote gateway.
pub trait TrustlessRecipientKeyring {
    fn keyring_name(&self) -> &'static str;

    fn encrypt_with_recipient_envelopes(
        &self,
        plaintext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError>;

    fn decrypt_with_local_recipient_key(
        &self,
        ciphertext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyringError {
    #[error(
        "trustless recipient AWS Encryption SDK for Rust keyring encryption is not implemented yet"
    )]
    EncryptNotImplemented,

    #[error(
        "trustless recipient AWS Encryption SDK for Rust keyring decryption is not implemented yet"
    )]
    DecryptNotImplemented,

    #[error("AWS Encryption SDK for Rust adapter is not wired yet")]
    AwsEsdkAdapterNotWired,

    #[error("plaintext payload is required for trustless keyring encryption")]
    MissingPlaintextPayload,

    #[error("ciphertext payload is required for trustless keyring decryption")]
    MissingCiphertextPayload,

    #[error("recipient envelope bucket id is required")]
    MissingBucketId,

    #[error("recipient envelope object key id is required")]
    MissingObjectKeyId,

    #[error("at least one recipient envelope is required")]
    MissingRecipientEnvelopes,

    #[error("recipient envelope is disabled: {0}")]
    DisabledRecipientEnvelope(String),

    #[error("recipient public encryption key is empty: {0}")]
    EmptyRecipientPublicKey(String),

    #[error("recipient encryption key type is empty: {0}")]
    EmptyRecipientKeyType(String),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnimplementedTrustlessRecipientKeyring;

impl TrustlessRecipientKeyring for UnimplementedTrustlessRecipientKeyring {
    fn keyring_name(&self) -> &'static str {
        "trustless-recipient-keyring"
    }

    fn encrypt_with_recipient_envelopes(
        &self,
        _plaintext: &[u8],
        _context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        Err(KeyringError::EncryptNotImplemented)
    }

    fn decrypt_with_local_recipient_key(
        &self,
        _ciphertext: &[u8],
        _context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, KeyringError> {
        Err(KeyringError::DecryptNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
        }
    }

    #[test]
    fn placeholder_keyring_fails_closed_for_encryption() {
        let keyring = UnimplementedTrustlessRecipientKeyring;

        assert_eq!(keyring.keyring_name(), "trustless-recipient-keyring");
        assert_eq!(
            keyring.encrypt_with_recipient_envelopes(b"plaintext", &context()),
            Err(KeyringError::EncryptNotImplemented)
        );
    }

    #[test]
    fn placeholder_keyring_fails_closed_for_decryption() {
        let keyring = UnimplementedTrustlessRecipientKeyring;

        assert_eq!(
            keyring.decrypt_with_local_recipient_key(b"ciphertext", &context()),
            Err(KeyringError::DecryptNotImplemented)
        );
    }
}
