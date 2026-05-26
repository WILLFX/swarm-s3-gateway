use thiserror::Error;

use crate::encryption::{
    TrustlessDecryptRequest, TrustlessDecryptResult, TrustlessEncryptRequest,
    TrustlessEncryptionBoundary, TrustlessEncryptionError,
};
use crate::gateway_boundary::{
    CiphertextGatewayBoundary, CiphertextGatewayBoundaryError, CiphertextGatewayRequest,
    CiphertextGatewayResponse,
};
use crate::keyring::TrustlessRecipientKeyring;
use crate::manifest::{
    EncryptedTrustlessManifest, TrustlessManifest, TrustlessManifestBoundary,
    TrustlessManifestCipher, TrustlessManifestEntry, TrustlessManifestError,
    TrustlessManifestListResult,
};
use crate::preflight::{TrustlessLocalDecryptPreflight, TrustlessPutPreflight};
use crate::types::RecipientEnvelopeContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPutOperationInput {
    pub plaintext: Vec<u8>,
    pub preflight: TrustlessPutPreflight,
    pub current_manifest: TrustlessManifest,
    pub manifest_entry: TrustlessManifestEntry,
    pub manifest_envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessPutOperationPlan {
    pub object_request: CiphertextGatewayRequest,
    pub encrypted_manifest: EncryptedTrustlessManifest,
    pub remote_payloads_are_ciphertext_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessDeleteOperationInput {
    pub preflight: TrustlessLocalDecryptPreflight,
    pub current_manifest: TrustlessManifest,
    pub object_key_id: String,
    pub manifest_envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessDeleteOperationPlan {
    pub delete_request: CiphertextGatewayRequest,
    pub encrypted_manifest: EncryptedTrustlessManifest,
    pub remote_payloads_are_ciphertext_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessOperationError {
    #[error("gateway response did not include ciphertext payload")]
    MissingCiphertextResponse,

    #[error("gateway response did not include encrypted manifest payload")]
    MissingEncryptedManifestResponse,

    #[error(transparent)]
    Encryption(TrustlessEncryptionError),

    #[error(transparent)]
    Gateway(CiphertextGatewayBoundaryError),

    #[error(transparent)]
    Manifest(TrustlessManifestError),
}

impl From<TrustlessEncryptionError> for TrustlessOperationError {
    fn from(error: TrustlessEncryptionError) -> Self {
        Self::Encryption(error)
    }
}

impl From<CiphertextGatewayBoundaryError> for TrustlessOperationError {
    fn from(error: CiphertextGatewayBoundaryError) -> Self {
        Self::Gateway(error)
    }
}

impl From<TrustlessManifestError> for TrustlessOperationError {
    fn from(error: TrustlessManifestError) -> Self {
        Self::Manifest(error)
    }
}

pub struct TrustlessOperationAssembler<K, C> {
    encryption: TrustlessEncryptionBoundary<K>,
    manifest: TrustlessManifestBoundary<C>,
}

impl<K, C> TrustlessOperationAssembler<K, C>
where
    K: TrustlessRecipientKeyring,
    C: TrustlessManifestCipher,
{
    pub fn new(keyring: K, manifest_cipher: C) -> Self {
        Self {
            encryption: TrustlessEncryptionBoundary::new(keyring),
            manifest: TrustlessManifestBoundary::new(manifest_cipher),
        }
    }

    pub fn prepare_put(
        &self,
        input: TrustlessPutOperationInput,
    ) -> Result<TrustlessPutOperationPlan, TrustlessOperationError> {
        let route_plan = input.preflight.route_plan.clone();

        let encrypted_object = self.encryption.encrypt_for_put(TrustlessEncryptRequest {
            plaintext: input.plaintext,
            preflight: input.preflight,
        })?;

        let object_request =
            CiphertextGatewayBoundary::put_ciphertext_request(&route_plan, encrypted_object)?;

        let manifest_mutation = self
            .manifest
            .upsert_entry_locally(input.current_manifest, input.manifest_entry)?;

        let manifest_write = self.manifest.encrypt_manifest_locally(
            manifest_mutation.manifest,
            input.manifest_envelope_context,
        )?;

        Ok(TrustlessPutOperationPlan {
            object_request,
            encrypted_manifest: manifest_write.encrypted_manifest,
            remote_payloads_are_ciphertext_only: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn prepare_get_request(
        &self,
        preflight: &TrustlessLocalDecryptPreflight,
    ) -> Result<CiphertextGatewayRequest, TrustlessOperationError> {
        Ok(CiphertextGatewayBoundary::get_ciphertext_request(
            &preflight.route_plan,
        )?)
    }

    pub fn complete_get_response(
        &self,
        preflight: TrustlessLocalDecryptPreflight,
        response: CiphertextGatewayResponse,
        envelope_context: RecipientEnvelopeContext,
    ) -> Result<TrustlessDecryptResult, TrustlessOperationError> {
        let response = CiphertextGatewayBoundary::validate_response(response)?;

        let Some(ciphertext) = response.ciphertext_payload else {
            return Err(TrustlessOperationError::MissingCiphertextResponse);
        };

        Ok(self.encryption.decrypt_locally(TrustlessDecryptRequest {
            ciphertext,
            preflight,
            envelope_context,
        })?)
    }

    pub fn prepare_list_request(
        &self,
        preflight: &TrustlessLocalDecryptPreflight,
    ) -> Result<CiphertextGatewayRequest, TrustlessOperationError> {
        Ok(CiphertextGatewayBoundary::list_encrypted_manifest_request(
            &preflight.route_plan,
        )?)
    }

    pub fn complete_list_response(
        &self,
        response: CiphertextGatewayResponse,
        envelope_context: RecipientEnvelopeContext,
        prefix: Option<&str>,
    ) -> Result<TrustlessManifestListResult, TrustlessOperationError> {
        let response = CiphertextGatewayBoundary::validate_response(response)?;

        let Some(ciphertext) = response.encrypted_manifest_payload else {
            return Err(TrustlessOperationError::MissingEncryptedManifestResponse);
        };

        let read = self
            .manifest
            .decrypt_manifest_locally(EncryptedTrustlessManifest {
                ciphertext,
                envelope_context,
                gateway_plaintext_access: false,
            })?;

        Ok(self
            .manifest
            .list_metadata_locally(&read.manifest, prefix)?)
    }

    pub fn prepare_delete(
        &self,
        input: TrustlessDeleteOperationInput,
    ) -> Result<TrustlessDeleteOperationPlan, TrustlessOperationError> {
        let manifest_mutation = self
            .manifest
            .remove_entry_locally(input.current_manifest, input.object_key_id)?;

        let manifest_write = self.manifest.encrypt_manifest_locally(
            manifest_mutation.manifest,
            input.manifest_envelope_context,
        )?;

        let delete_request = CiphertextGatewayBoundary::delete_ciphertext_request(
            &input.preflight.route_plan,
            manifest_write.encrypted_manifest.ciphertext.clone(),
        )?;

        Ok(TrustlessDeleteOperationPlan {
            delete_request,
            encrypted_manifest: manifest_write.encrypted_manifest,
            remote_payloads_are_ciphertext_only: true,
            gateway_plaintext_access: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_boundary::CiphertextGatewayResponse;
    use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
    use crate::local_keystore::LocalPrivateKeySelection;
    use crate::manifest::{TrustlessManifestCipher, TrustlessManifestError};
    use crate::planner::{RemoteGatewayAction, TrustlessProxyOperation, TrustlessRoutePlan};
    use crate::preflight::{TrustlessLocalDecryptPreflight, TrustlessPutPreflight};
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

    #[derive(Debug, Clone, Copy)]
    struct MockManifestCipher;

    impl TrustlessManifestCipher for MockManifestCipher {
        fn decrypt_manifest(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<TrustlessManifest, TrustlessManifestError> {
            if ciphertext != b"encrypted-manifest" {
                return Err(TrustlessManifestError::Cipher(
                    "unexpected encrypted manifest".to_owned(),
                ));
            }

            Ok(manifest())
        }

        fn encrypt_manifest(
            &self,
            manifest: &TrustlessManifest,
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, TrustlessManifestError> {
            Ok(format!(
                "encrypted-manifest:{}:{}",
                manifest.bucket_id, manifest.manifest_version
            )
            .into_bytes())
        }
    }

    fn assembler() -> TrustlessOperationAssembler<MockKeyring, MockManifestCipher> {
        TrustlessOperationAssembler::new(MockKeyring, MockManifestCipher)
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

    fn route_plan(
        operation: TrustlessProxyOperation,
        action: RemoteGatewayAction,
    ) -> TrustlessRoutePlan {
        TrustlessRoutePlan {
            operation,
            bucket_type: TrustlessBucketType::TrustlessPrivate,
            bucket: "bucket".to_owned(),
            key: Some("secret.txt".to_owned()),
            local_steps: Vec::new(),
            remote_action: action,
            ciphertext_only_remote: true,
            gateway_plaintext_access: false,
        }
    }

    fn put_preflight() -> TrustlessPutPreflight {
        TrustlessPutPreflight {
            route_plan: route_plan(
                TrustlessProxyOperation::PutObject,
                RemoteGatewayAction::PutCiphertextObject,
            ),
            envelope_context: envelope_context(),
            local_private_key: local_private_key(),
        }
    }

    fn get_preflight() -> TrustlessLocalDecryptPreflight {
        TrustlessLocalDecryptPreflight {
            route_plan: route_plan(
                TrustlessProxyOperation::GetObject,
                RemoteGatewayAction::GetCiphertextObject,
            ),
            local_private_key: local_private_key(),
        }
    }

    fn list_preflight() -> TrustlessLocalDecryptPreflight {
        let mut plan = route_plan(
            TrustlessProxyOperation::ListObjectsV2,
            RemoteGatewayAction::ListCiphertextManifest,
        );
        plan.key = None;

        TrustlessLocalDecryptPreflight {
            route_plan: plan,
            local_private_key: local_private_key(),
        }
    }

    fn delete_preflight() -> TrustlessLocalDecryptPreflight {
        TrustlessLocalDecryptPreflight {
            route_plan: route_plan(
                TrustlessProxyOperation::DeleteObject,
                RemoteGatewayAction::DeleteCiphertextObject,
            ),
            local_private_key: local_private_key(),
        }
    }

    fn entry(object_key: &str, object_key_id: &str) -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: object_key.to_owned(),
            object_key_id: object_key_id.to_owned(),
            ciphertext_ref: format!("swarm://ciphertext/{object_key_id}"),
            ciphertext_size: 128,
            content_type: Some("text/plain".to_owned()),
            etag: Some(format!("etag-{object_key_id}")),
        }
    }

    fn manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([1u8; 32]),
            manifest_version: 1,
            entries: vec![entry("docs/a.txt", "object-a")],
        }
    }

    #[test]
    fn put_operation_encrypts_object_and_manifest_locally() {
        let plan = assembler()
            .prepare_put(TrustlessPutOperationInput {
                plaintext: b"secret".to_vec(),
                preflight: put_preflight(),
                current_manifest: manifest(),
                manifest_entry: entry("docs/b.txt", "object-b"),
                manifest_envelope_context: envelope_context(),
            })
            .unwrap();

        assert_eq!(
            plan.object_request.action,
            RemoteGatewayAction::PutCiphertextObject
        );
        assert_eq!(
            plan.object_request.ciphertext_payload,
            Some(b"ciphertext:secret".to_vec())
        );
        assert!(plan.remote_payloads_are_ciphertext_only);
        assert!(!plan.gateway_plaintext_access);
        assert!(!plan.encrypted_manifest.ciphertext.is_empty());
        assert!(!plan.encrypted_manifest.gateway_plaintext_access);
    }

    #[test]
    fn get_operation_prepares_ciphertext_request_and_decrypts_response_locally() {
        let request = assembler().prepare_get_request(&get_preflight()).unwrap();

        assert_eq!(request.action, RemoteGatewayAction::GetCiphertextObject);
        assert!(!request.plaintext_payload_present);

        let result = assembler()
            .complete_get_response(
                get_preflight(),
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(b"ciphertext:secret".to_vec()),
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context(),
            )
            .unwrap();

        assert_eq!(result.plaintext, b"secret".to_vec());
        assert!(result.decrypted_locally);
        assert!(!result.gateway_plaintext_access);
    }

    #[test]
    fn list_operation_fetches_encrypted_manifest_and_lists_metadata_locally() {
        let request = assembler().prepare_list_request(&list_preflight()).unwrap();

        assert_eq!(request.action, RemoteGatewayAction::ListCiphertextManifest);
        assert!(!request.plaintext_payload_present);

        let result = assembler()
            .complete_list_response(
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::ListCiphertextManifest,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: Some(b"encrypted-manifest".to_vec()),
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context(),
                Some("docs/"),
            )
            .unwrap();

        assert!(result.metadata_only);
        assert!(result.read_from_decrypted_manifest_only);
        assert!(!result.gateway_plaintext_access);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn delete_operation_updates_and_encrypts_manifest_locally() {
        let plan = assembler()
            .prepare_delete(TrustlessDeleteOperationInput {
                preflight: delete_preflight(),
                current_manifest: manifest(),
                object_key_id: "object-a".to_owned(),
                manifest_envelope_context: envelope_context(),
            })
            .unwrap();

        assert_eq!(
            plan.delete_request.action,
            RemoteGatewayAction::DeleteCiphertextObject
        );
        assert!(plan.delete_request.ciphertext_payload.is_none());
        assert!(plan.delete_request.encrypted_manifest_payload.is_some());
        assert!(plan.remote_payloads_are_ciphertext_only);
        assert!(!plan.gateway_plaintext_access);
    }

    #[test]
    fn operation_assembly_rejects_missing_ciphertext_or_manifest_responses() {
        let err = assembler()
            .complete_get_response(
                get_preflight(),
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context(),
            )
            .unwrap_err();

        assert_eq!(err, TrustlessOperationError::MissingCiphertextResponse);

        let err = assembler()
            .complete_list_response(
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::ListCiphertextManifest,
                    ciphertext_payload: None,
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: false,
                },
                envelope_context(),
                None,
            )
            .unwrap_err();

        assert_eq!(
            err,
            TrustlessOperationError::MissingEncryptedManifestResponse
        );
    }

    #[test]
    fn operation_assembly_rejects_gateway_plaintext_response() {
        let err = assembler()
            .complete_get_response(
                get_preflight(),
                CiphertextGatewayResponse {
                    action: RemoteGatewayAction::GetCiphertextObject,
                    ciphertext_payload: Some(b"ciphertext:secret".to_vec()),
                    encrypted_manifest_payload: None,
                    metadata_only: false,
                    gateway_plaintext_access: true,
                },
                envelope_context(),
            )
            .unwrap_err();

        assert_eq!(
            err,
            TrustlessOperationError::Gateway(
                CiphertextGatewayBoundaryError::GatewayPlaintextAccessRejected
            )
        );
    }
}
