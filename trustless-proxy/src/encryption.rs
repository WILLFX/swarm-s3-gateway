use thiserror::Error;

use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
use crate::preflight::{TrustlessLocalDecryptPreflight, TrustlessPutPreflight};
use crate::types::RecipientEnvelopeContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessEncryptRequest {
    pub plaintext: Vec<u8>,
    pub preflight: TrustlessPutPreflight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessEncryptResult {
    pub ciphertext: Vec<u8>,
    pub envelope_context: RecipientEnvelopeContext,
    pub remote_payload_is_ciphertext_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessDecryptRequest {
    pub ciphertext: Vec<u8>,
    pub preflight: TrustlessLocalDecryptPreflight,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessDecryptResult {
    pub plaintext: Vec<u8>,
    pub decrypted_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessEncryptionError {
    #[error("plaintext payload is required for trustless encryption")]
    MissingPlaintext,

    #[error("ciphertext payload is required for trustless decryption")]
    MissingCiphertext,

    #[error("trustless route plan does not require ciphertext-only remote forwarding")]
    RouteAllowsNonCiphertextRemotePayload,

    #[error("trustless route plan would allow gateway plaintext access")]
    RouteAllowsGatewayPlaintextAccess,

    #[error(transparent)]
    Keyring(KeyringError),
}

impl From<KeyringError> for TrustlessEncryptionError {
    fn from(error: KeyringError) -> Self {
        Self::Keyring(error)
    }
}

pub struct TrustlessEncryptionBoundary<K> {
    keyring: K,
}

impl<K> TrustlessEncryptionBoundary<K>
where
    K: TrustlessRecipientKeyring,
{
    pub fn new(keyring: K) -> Self {
        Self { keyring }
    }

    pub fn encrypt_for_put(
        &self,
        request: TrustlessEncryptRequest,
    ) -> Result<TrustlessEncryptResult, TrustlessEncryptionError> {
        if request.plaintext.is_empty() {
            return Err(TrustlessEncryptionError::MissingPlaintext);
        }

        enforce_ciphertext_only_route(
            request.preflight.route_plan.ciphertext_only_remote,
            request.preflight.route_plan.gateway_plaintext_access,
        )?;

        let ciphertext = self.keyring.encrypt_with_recipient_envelopes(
            &request.plaintext,
            &request.preflight.envelope_context,
        )?;

        Ok(TrustlessEncryptResult {
            ciphertext,
            envelope_context: request.preflight.envelope_context,
            remote_payload_is_ciphertext_only: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn decrypt_locally(
        &self,
        request: TrustlessDecryptRequest,
    ) -> Result<TrustlessDecryptResult, TrustlessEncryptionError> {
        if request.ciphertext.is_empty() {
            return Err(TrustlessEncryptionError::MissingCiphertext);
        }

        enforce_ciphertext_only_route(
            request.preflight.route_plan.ciphertext_only_remote,
            request.preflight.route_plan.gateway_plaintext_access,
        )?;

        let plaintext = self
            .keyring
            .decrypt_with_local_recipient_key(&request.ciphertext, &request.envelope_context)?;

        Ok(TrustlessDecryptResult {
            plaintext,
            decrypted_locally: true,
            gateway_plaintext_access: false,
        })
    }
}

fn enforce_ciphertext_only_route(
    ciphertext_only_remote: bool,
    gateway_plaintext_access: bool,
) -> Result<(), TrustlessEncryptionError> {
    if !ciphertext_only_remote {
        return Err(TrustlessEncryptionError::RouteAllowsNonCiphertextRemotePayload);
    }

    if gateway_plaintext_access {
        return Err(TrustlessEncryptionError::RouteAllowsGatewayPlaintextAccess);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::TrustlessRecipientKeyring;
    use crate::local_keystore::LocalPrivateKeySelection;
    use crate::planner::{RemoteGatewayAction, TrustlessProxyOperation, TrustlessRoutePlan};
    use crate::types::{RecipientEnvelopeContext, TrustlessBucketType};

    #[derive(Debug, Clone, Copy)]
    struct MockKeyring;

    impl TrustlessRecipientKeyring for MockKeyring {
        fn keyring_name(&self) -> &'static str {
            "mock-trustless-keyring"
        }

        fn encrypt_with_recipient_envelopes(
            &self,
            plaintext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, KeyringError> {
            let mut ciphertext = b"ciphertext:".to_vec();
            ciphertext.extend_from_slice(plaintext);
            Ok(ciphertext)
        }

        fn decrypt_with_local_recipient_key(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, KeyringError> {
            let prefix = b"ciphertext:";
            if let Some(plaintext) = ciphertext.strip_prefix(prefix) {
                Ok(plaintext.to_vec())
            } else {
                Err(KeyringError::DecryptNotImplemented)
            }
        }
    }

    fn envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
        }
    }

    fn local_private_key() -> LocalPrivateKeySelection {
        LocalPrivateKeySelection {
            account: "alice".to_owned(),
            key_type: "aws-esdk-rust-recipient-key".to_owned(),
            key_version: 1,
            encrypted_private_key_blob: vec![1, 2, 3],
            storage_label: "local-keystore/alice/1".to_owned(),
        }
    }

    fn route_plan(operation: TrustlessProxyOperation) -> TrustlessRoutePlan {
        TrustlessRoutePlan {
            operation,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            local_steps: Vec::new(),
            remote_action: match operation {
                TrustlessProxyOperation::PutObject => RemoteGatewayAction::PutCiphertextObject,
                TrustlessProxyOperation::GetObject => RemoteGatewayAction::GetCiphertextObject,
                TrustlessProxyOperation::DeleteObject => {
                    RemoteGatewayAction::DeleteCiphertextObject
                }
                TrustlessProxyOperation::HeadObject => RemoteGatewayAction::HeadCiphertextObject,
                TrustlessProxyOperation::ListObjectsV2 => {
                    RemoteGatewayAction::ListCiphertextManifest
                }
            },
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        }
    }

    fn put_preflight() -> TrustlessPutPreflight {
        TrustlessPutPreflight {
            route_plan: route_plan(TrustlessProxyOperation::PutObject),
            envelope_context: envelope_context(),
            local_private_key: local_private_key(),
        }
    }

    fn decrypt_preflight() -> TrustlessLocalDecryptPreflight {
        TrustlessLocalDecryptPreflight {
            route_plan: route_plan(TrustlessProxyOperation::GetObject),
            local_private_key: local_private_key(),
        }
    }

    #[test]
    fn encrypt_for_put_returns_ciphertext_only_remote_payload() {
        let boundary = TrustlessEncryptionBoundary::new(MockKeyring);

        let result = boundary
            .encrypt_for_put(TrustlessEncryptRequest {
                plaintext: b"secret".to_vec(),
                preflight: put_preflight(),
            })
            .unwrap();

        assert_eq!(result.ciphertext, b"ciphertext:secret".to_vec());
        assert!(result.remote_payload_is_ciphertext_only);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn decrypt_locally_returns_plaintext_without_gateway_plaintext_access() {
        let boundary = TrustlessEncryptionBoundary::new(MockKeyring);

        let result = boundary
            .decrypt_locally(TrustlessDecryptRequest {
                ciphertext: b"ciphertext:secret".to_vec(),
                preflight: decrypt_preflight(),
                envelope_context: envelope_context(),
            })
            .unwrap();

        assert_eq!(result.plaintext, b"secret".to_vec());
        assert!(result.decrypted_locally);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn encryption_rejects_empty_plaintext_or_ciphertext() {
        let boundary = TrustlessEncryptionBoundary::new(MockKeyring);

        assert_eq!(
            boundary
                .encrypt_for_put(TrustlessEncryptRequest {
                    plaintext: Vec::new(),
                    preflight: put_preflight(),
                })
                .unwrap_err(),
            TrustlessEncryptionError::MissingPlaintext
        );

        assert_eq!(
            boundary
                .decrypt_locally(TrustlessDecryptRequest {
                    ciphertext: Vec::new(),
                    preflight: decrypt_preflight(),
                    envelope_context: envelope_context(),
                })
                .unwrap_err(),
            TrustlessEncryptionError::MissingCiphertext
        );
    }

    #[test]
    fn encryption_rejects_route_that_is_not_ciphertext_only() {
        let boundary = TrustlessEncryptionBoundary::new(MockKeyring);
        let mut preflight = put_preflight();
        preflight.route_plan.ciphertext_only_remote = false;

        assert_eq!(
            boundary
                .encrypt_for_put(TrustlessEncryptRequest {
                    plaintext: b"secret".to_vec(),
                    preflight,
                })
                .unwrap_err(),
            TrustlessEncryptionError::RouteAllowsNonCiphertextRemotePayload
        );
    }

    #[test]
    fn encryption_rejects_route_that_allows_gateway_plaintext_access() {
        let boundary = TrustlessEncryptionBoundary::new(MockKeyring);
        let mut preflight = put_preflight();
        preflight.route_plan.gateway_plaintext_access = true;

        assert_eq!(
            boundary
                .encrypt_for_put(TrustlessEncryptRequest {
                    plaintext: b"secret".to_vec(),
                    preflight,
                })
                .unwrap_err(),
            TrustlessEncryptionError::RouteAllowsGatewayPlaintextAccess
        );
    }
}
