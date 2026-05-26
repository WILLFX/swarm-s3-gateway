use thiserror::Error;

use crate::types::RecipientEnvelopeContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifestEntry {
    pub object_key: String,
    pub object_key_id: String,
    pub ciphertext_ref: String,
    pub ciphertext_size: u64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifest {
    pub bucket_id: String,
    pub manifest_version: u64,
    pub entries: Vec<TrustlessManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedTrustlessManifest {
    pub ciphertext: Vec<u8>,
    pub envelope_context: RecipientEnvelopeContext,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifestRead {
    pub manifest: TrustlessManifest,
    pub decrypted_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifestWrite {
    pub encrypted_manifest: EncryptedTrustlessManifest,
    pub encrypted_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifestMutation {
    pub manifest: TrustlessManifest,
    pub mutated_locally: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessManifestListResult {
    pub entries: Vec<TrustlessManifestEntry>,
    pub metadata_only: bool,
    pub read_from_decrypted_manifest_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessManifestError {
    #[error("encrypted manifest ciphertext is required")]
    MissingEncryptedManifest,

    #[error("manifest encryption returned empty ciphertext")]
    EmptyEncryptedManifestOutput,

    #[error("bucket id is required")]
    MissingBucketId,

    #[error("object key is required")]
    MissingObjectKey,

    #[error("object key id is required")]
    MissingObjectKeyId,

    #[error("ciphertext reference is required")]
    MissingCiphertextReference,

    #[error("manifest entry was not found: {0}")]
    ManifestEntryNotFound(String),

    #[error("gateway plaintext access is not allowed for trustless manifests")]
    GatewayPlaintextAccessRejected,

    #[error("manifest cipher failed: {0}")]
    Cipher(String),
}

pub trait TrustlessManifestCipher {
    fn decrypt_manifest(
        &self,
        ciphertext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<TrustlessManifest, TrustlessManifestError>;

    fn encrypt_manifest(
        &self,
        manifest: &TrustlessManifest,
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, TrustlessManifestError>;
}

pub struct TrustlessManifestBoundary<C> {
    cipher: C,
}

impl<C> TrustlessManifestBoundary<C>
where
    C: TrustlessManifestCipher,
{
    pub fn new(cipher: C) -> Self {
        Self { cipher }
    }

    pub fn decrypt_manifest_locally(
        &self,
        encrypted: EncryptedTrustlessManifest,
    ) -> Result<TrustlessManifestRead, TrustlessManifestError> {
        if encrypted.gateway_plaintext_access {
            return Err(TrustlessManifestError::GatewayPlaintextAccessRejected);
        }

        if encrypted.ciphertext.is_empty() {
            return Err(TrustlessManifestError::MissingEncryptedManifest);
        }

        let manifest = self
            .cipher
            .decrypt_manifest(&encrypted.ciphertext, &encrypted.envelope_context)?;

        validate_manifest(&manifest)?;

        Ok(TrustlessManifestRead {
            manifest,
            decrypted_locally: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn encrypt_manifest_locally(
        &self,
        manifest: TrustlessManifest,
        envelope_context: RecipientEnvelopeContext,
    ) -> Result<TrustlessManifestWrite, TrustlessManifestError> {
        validate_manifest(&manifest)?;

        let ciphertext = self.cipher.encrypt_manifest(&manifest, &envelope_context)?;

        if ciphertext.is_empty() {
            return Err(TrustlessManifestError::EmptyEncryptedManifestOutput);
        }

        Ok(TrustlessManifestWrite {
            encrypted_manifest: EncryptedTrustlessManifest {
                ciphertext,
                envelope_context,
                gateway_plaintext_access: false,
            },
            encrypted_locally: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn upsert_entry_locally(
        &self,
        mut manifest: TrustlessManifest,
        entry: TrustlessManifestEntry,
    ) -> Result<TrustlessManifestMutation, TrustlessManifestError> {
        validate_manifest(&manifest)?;
        validate_entry(&entry)?;

        if let Some(existing) = manifest
            .entries
            .iter_mut()
            .find(|existing| existing.object_key_id == entry.object_key_id)
        {
            *existing = entry;
        } else {
            manifest.entries.push(entry);
        }

        manifest
            .entries
            .sort_by(|left, right| left.object_key_id.cmp(&right.object_key_id));
        manifest.manifest_version = manifest.manifest_version.saturating_add(1);

        Ok(TrustlessManifestMutation {
            manifest,
            mutated_locally: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn remove_entry_locally(
        &self,
        mut manifest: TrustlessManifest,
        object_key_id: impl Into<String>,
    ) -> Result<TrustlessManifestMutation, TrustlessManifestError> {
        validate_manifest(&manifest)?;

        let object_key_id = object_key_id.into().trim().to_owned();

        if object_key_id.is_empty() {
            return Err(TrustlessManifestError::MissingObjectKeyId);
        }

        let before = manifest.entries.len();
        manifest
            .entries
            .retain(|entry| entry.object_key_id != object_key_id);

        if manifest.entries.len() == before {
            return Err(TrustlessManifestError::ManifestEntryNotFound(object_key_id));
        }

        manifest.manifest_version = manifest.manifest_version.saturating_add(1);

        Ok(TrustlessManifestMutation {
            manifest,
            mutated_locally: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn list_metadata_locally(
        &self,
        manifest: &TrustlessManifest,
        prefix: Option<&str>,
    ) -> Result<TrustlessManifestListResult, TrustlessManifestError> {
        validate_manifest(manifest)?;

        let entries = manifest
            .entries
            .iter()
            .filter(|entry| {
                prefix
                    .map(|prefix| entry.object_key.starts_with(prefix))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();

        Ok(TrustlessManifestListResult {
            entries,
            metadata_only: true,
            read_from_decrypted_manifest_only: true,
            gateway_plaintext_access: false,
        })
    }
}

fn validate_manifest(manifest: &TrustlessManifest) -> Result<(), TrustlessManifestError> {
    if manifest.bucket_id.trim().is_empty() {
        return Err(TrustlessManifestError::MissingBucketId);
    }

    for entry in &manifest.entries {
        validate_entry(entry)?;
    }

    Ok(())
}

fn validate_entry(entry: &TrustlessManifestEntry) -> Result<(), TrustlessManifestError> {
    if entry.object_key.trim().is_empty() {
        return Err(TrustlessManifestError::MissingObjectKey);
    }

    if entry.object_key_id.trim().is_empty() {
        return Err(TrustlessManifestError::MissingObjectKeyId);
    }

    if entry.ciphertext_ref.trim().is_empty() {
        return Err(TrustlessManifestError::MissingCiphertextReference);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    "unexpected manifest ciphertext".to_owned(),
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

    fn envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([1u8; 32]),
            object_key_id: hex::encode([2u8; 32]),
            policy_version: 1,
            recipients: Vec::new(),
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
            entries: vec![
                entry("docs/a.txt", "object-a"),
                entry("images/b.png", "object-b"),
            ],
        }
    }

    #[test]
    fn decrypt_manifest_locally_returns_manifest_without_gateway_plaintext_access() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let read = boundary
            .decrypt_manifest_locally(EncryptedTrustlessManifest {
                ciphertext: b"encrypted-manifest".to_vec(),
                envelope_context: envelope_context(),
                gateway_plaintext_access: false,
            })
            .unwrap();

        assert!(read.decrypted_locally);
        assert!(!read.gateway_plaintext_access);
        assert_eq!(read.manifest.entries.len(), 2);
    }

    #[test]
    fn encrypt_manifest_locally_returns_encrypted_manifest_only() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let write = boundary
            .encrypt_manifest_locally(manifest(), envelope_context())
            .unwrap();

        assert!(write.encrypted_locally);
        assert!(!write.gateway_plaintext_access);
        assert_eq!(
            write.encrypted_manifest.ciphertext,
            format!("encrypted-manifest:{}:1", hex::encode([1u8; 32])).into_bytes()
        );
        assert!(!write.encrypted_manifest.gateway_plaintext_access);
    }

    #[test]
    fn upsert_entry_locally_replaces_existing_entry_and_increments_version() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let mutation = boundary
            .upsert_entry_locally(
                manifest(),
                TrustlessManifestEntry {
                    ciphertext_size: 999,
                    ..entry("docs/a.txt", "object-a")
                },
            )
            .unwrap();

        assert!(mutation.mutated_locally);
        assert!(!mutation.gateway_plaintext_access);
        assert_eq!(mutation.manifest.manifest_version, 2);
        assert_eq!(mutation.manifest.entries.len(), 2);
        assert_eq!(mutation.manifest.entries[0].ciphertext_size, 999);
    }

    #[test]
    fn upsert_entry_locally_adds_new_entry_deterministically() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let mutation = boundary
            .upsert_entry_locally(manifest(), entry("docs/c.txt", "object-c"))
            .unwrap();

        let ids = mutation
            .manifest
            .entries
            .iter()
            .map(|entry| entry.object_key_id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["object-a", "object-b", "object-c"]);
        assert_eq!(mutation.manifest.manifest_version, 2);
    }

    #[test]
    fn remove_entry_locally_removes_entry_and_fails_when_missing() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let mutation = boundary
            .remove_entry_locally(manifest(), "object-a")
            .unwrap();

        assert_eq!(mutation.manifest.manifest_version, 2);
        assert_eq!(mutation.manifest.entries.len(), 1);
        assert_eq!(mutation.manifest.entries[0].object_key_id, "object-b");

        let err = boundary
            .remove_entry_locally(manifest(), "missing-object")
            .unwrap_err();

        assert_eq!(
            err,
            TrustlessManifestError::ManifestEntryNotFound("missing-object".to_owned())
        );
    }

    #[test]
    fn list_metadata_locally_uses_decrypted_manifest_entries_only() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        let result = boundary
            .list_metadata_locally(&manifest(), Some("docs/"))
            .unwrap();

        assert!(result.metadata_only);
        assert!(result.read_from_decrypted_manifest_only);
        assert!(!result.gateway_plaintext_access);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].object_key, "docs/a.txt");
    }

    #[test]
    fn manifest_boundary_rejects_empty_or_gateway_plaintext_inputs() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        assert_eq!(
            boundary
                .decrypt_manifest_locally(EncryptedTrustlessManifest {
                    ciphertext: Vec::new(),
                    envelope_context: envelope_context(),
                    gateway_plaintext_access: false,
                })
                .unwrap_err(),
            TrustlessManifestError::MissingEncryptedManifest
        );

        assert_eq!(
            boundary
                .decrypt_manifest_locally(EncryptedTrustlessManifest {
                    ciphertext: b"encrypted-manifest".to_vec(),
                    envelope_context: envelope_context(),
                    gateway_plaintext_access: true,
                })
                .unwrap_err(),
            TrustlessManifestError::GatewayPlaintextAccessRejected
        );
    }

    #[test]
    fn manifest_boundary_rejects_malformed_manifest_entries() {
        let boundary = TrustlessManifestBoundary::new(MockManifestCipher);

        assert_eq!(
            boundary
                .upsert_entry_locally(
                    manifest(),
                    TrustlessManifestEntry {
                        object_key_id: " ".to_owned(),
                        ..entry("bad.txt", "bad")
                    },
                )
                .unwrap_err(),
            TrustlessManifestError::MissingObjectKeyId
        );

        assert_eq!(
            boundary
                .upsert_entry_locally(
                    manifest(),
                    TrustlessManifestEntry {
                        ciphertext_ref: " ".to_owned(),
                        ..entry("bad.txt", "bad")
                    },
                )
                .unwrap_err(),
            TrustlessManifestError::MissingCiphertextReference
        );
    }
}
