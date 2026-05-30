use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keyring::TrustlessRecipientKeyring;
use crate::manifest::{
    TrustlessManifest, TrustlessManifestCipher, TrustlessManifestEntry, TrustlessManifestError,
};
use crate::types::RecipientEnvelopeContext;

const MANIFEST_SCHEMA: &str = "s3w.trustless.manifest";
const MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default)]
pub struct TrustlessManifestJsonCodec;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestJsonDocument {
    schema: String,
    version: u32,
    bucket_id: String,
    manifest_version: u64,
    entries: Vec<ManifestJsonEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestJsonEntry {
    object_key_id: String,
    object_key: String,
    ciphertext_ref: String,
    ciphertext_size: u64,
    content_type: Option<String>,
    etag: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessManifestJsonCodecError {
    #[error("manifest JSON input is required")]
    EmptyInput,

    #[error("unsupported manifest JSON schema {schema} version {version}")]
    UnsupportedSchemaVersion { schema: String, version: u32 },

    #[error("duplicate manifest object key id: {0}")]
    DuplicateObjectKeyId(String),

    #[error("manifest JSON encode failed: {0}")]
    Encode(String),

    #[error("manifest JSON decode failed: {0}")]
    Decode(String),

    #[error(transparent)]
    Manifest(#[from] TrustlessManifestError),
}

impl TrustlessManifestJsonCodec {
    pub fn encode_manifest(
        manifest: &TrustlessManifest,
    ) -> Result<Vec<u8>, TrustlessManifestJsonCodecError> {
        let manifest = canonical_manifest(manifest)?;
        let document = ManifestJsonDocument::from_manifest(manifest);

        serde_json::to_vec(&document)
            .map_err(|error| TrustlessManifestJsonCodecError::Encode(error.to_string()))
    }

    pub fn decode_manifest(
        json: &[u8],
    ) -> Result<TrustlessManifest, TrustlessManifestJsonCodecError> {
        if json.is_empty() {
            return Err(TrustlessManifestJsonCodecError::EmptyInput);
        }

        let document: ManifestJsonDocument = serde_json::from_slice(json)
            .map_err(|error| TrustlessManifestJsonCodecError::Decode(error.to_string()))?;

        if document.schema != MANIFEST_SCHEMA || document.version != MANIFEST_SCHEMA_VERSION {
            return Err(TrustlessManifestJsonCodecError::UnsupportedSchemaVersion {
                schema: document.schema,
                version: document.version,
            });
        }

        let manifest = document.into_manifest();
        canonical_manifest(&manifest)
    }
}

impl ManifestJsonDocument {
    fn from_manifest(manifest: TrustlessManifest) -> Self {
        Self {
            schema: MANIFEST_SCHEMA.to_owned(),
            version: MANIFEST_SCHEMA_VERSION,
            bucket_id: manifest.bucket_id,
            manifest_version: manifest.manifest_version,
            entries: manifest
                .entries
                .into_iter()
                .map(ManifestJsonEntry::from_entry)
                .collect(),
        }
    }

    fn into_manifest(self) -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: self.bucket_id,
            manifest_version: self.manifest_version,
            entries: self
                .entries
                .into_iter()
                .map(ManifestJsonEntry::into_entry)
                .collect(),
        }
    }
}

impl ManifestJsonEntry {
    fn from_entry(entry: TrustlessManifestEntry) -> Self {
        Self {
            object_key_id: entry.object_key_id,
            object_key: entry.object_key,
            ciphertext_ref: entry.ciphertext_ref,
            ciphertext_size: entry.ciphertext_size,
            content_type: entry.content_type,
            etag: entry.etag,
        }
    }

    fn into_entry(self) -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key_id: self.object_key_id,
            object_key: self.object_key,
            ciphertext_ref: self.ciphertext_ref,
            ciphertext_size: self.ciphertext_size,
            content_type: self.content_type,
            etag: self.etag,
        }
    }
}

fn canonical_manifest(
    manifest: &TrustlessManifest,
) -> Result<TrustlessManifest, TrustlessManifestJsonCodecError> {
    validate_manifest(manifest)?;

    let mut entries = manifest.entries.clone();
    entries.sort_by(|left, right| {
        left.object_key_id
            .cmp(&right.object_key_id)
            .then_with(|| left.object_key.cmp(&right.object_key))
    });

    Ok(TrustlessManifest {
        bucket_id: manifest.bucket_id.trim().to_owned(),
        manifest_version: manifest.manifest_version,
        entries,
    })
}

fn validate_manifest(manifest: &TrustlessManifest) -> Result<(), TrustlessManifestJsonCodecError> {
    if manifest.bucket_id.trim().is_empty() {
        return Err(TrustlessManifestError::MissingBucketId.into());
    }

    let mut object_key_ids = BTreeSet::new();

    for entry in &manifest.entries {
        validate_entry(entry)?;

        let object_key_id = entry.object_key_id.trim().to_owned();

        if !object_key_ids.insert(object_key_id.clone()) {
            return Err(TrustlessManifestJsonCodecError::DuplicateObjectKeyId(
                object_key_id,
            ));
        }
    }

    Ok(())
}

fn validate_entry(entry: &TrustlessManifestEntry) -> Result<(), TrustlessManifestJsonCodecError> {
    if entry.object_key.trim().is_empty() {
        return Err(TrustlessManifestError::MissingObjectKey.into());
    }

    if entry.object_key_id.trim().is_empty() {
        return Err(TrustlessManifestError::MissingObjectKeyId.into());
    }

    if entry.ciphertext_ref.trim().is_empty() {
        return Err(TrustlessManifestError::MissingCiphertextReference.into());
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct AwsEsdkTrustlessManifestCipher<K> {
    keyring: K,
}

impl<K> AwsEsdkTrustlessManifestCipher<K> {
    pub fn new(keyring: K) -> Self {
        Self { keyring }
    }

    pub fn keyring(&self) -> &K {
        &self.keyring
    }
}

impl<K> TrustlessManifestCipher for AwsEsdkTrustlessManifestCipher<K>
where
    K: TrustlessRecipientKeyring,
{
    fn decrypt_manifest(
        &self,
        ciphertext: &[u8],
        context: &RecipientEnvelopeContext,
    ) -> Result<TrustlessManifest, TrustlessManifestError> {
        let plaintext = self
            .keyring
            .decrypt_with_local_recipient_key(ciphertext, context)
            .map_err(|error| TrustlessManifestError::Cipher(error.to_string()))?;

        TrustlessManifestJsonCodec::decode_manifest(&plaintext)
            .map_err(|error| TrustlessManifestError::Cipher(error.to_string()))
    }

    fn encrypt_manifest(
        &self,
        manifest: &TrustlessManifest,
        context: &RecipientEnvelopeContext,
    ) -> Result<Vec<u8>, TrustlessManifestError> {
        let plaintext = TrustlessManifestJsonCodec::encode_manifest(manifest)
            .map_err(|error| TrustlessManifestError::Cipher(error.to_string()))?;

        self.keyring
            .encrypt_with_recipient_envelopes(&plaintext, context)
            .map_err(|error| TrustlessManifestError::Cipher(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keyring::{KeyringError, TrustlessRecipientKeyring};
    use crate::types::{RecipientEncryptionKey, RecipientEnvelopeContext};

    #[derive(Debug, Clone, Copy)]
    struct MockManifestKeyring;

    impl TrustlessRecipientKeyring for MockManifestKeyring {
        fn keyring_name(&self) -> &'static str {
            "mock-manifest-keyring"
        }

        fn encrypt_with_recipient_envelopes(
            &self,
            plaintext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, KeyringError> {
            let mut ciphertext = b"manifest-ciphertext:".to_vec();
            ciphertext.extend_from_slice(plaintext);
            Ok(ciphertext)
        }

        fn decrypt_with_local_recipient_key(
            &self,
            ciphertext: &[u8],
            _context: &RecipientEnvelopeContext,
        ) -> Result<Vec<u8>, KeyringError> {
            ciphertext
                .strip_prefix(b"manifest-ciphertext:")
                .map(|plaintext| plaintext.to_vec())
                .ok_or(KeyringError::DecryptNotImplemented)
        }
    }

    fn manifest_envelope_context() -> RecipientEnvelopeContext {
        RecipientEnvelopeContext {
            bucket_id: hex::encode([9u8; 32]),
            object_key_id: hex::encode([8u8; 32]),
            policy_version: 1,
            recipients: vec![RecipientEncryptionKey {
                account: "alice".to_owned(),
                public_key: "alice-public-key".to_owned(),
                key_type: "aws-esdk-rust-recipient-key".to_owned(),
                key_version: 1,
                enabled: true,
            }],
        }
    }

    #[test]
    fn aws_esdk_manifest_cipher_round_trips_manifest_json_through_keyring() {
        let cipher = AwsEsdkTrustlessManifestCipher::new(MockManifestKeyring);
        let context = manifest_envelope_context();

        let encrypted = cipher
            .encrypt_manifest(&sample_manifest(), &context)
            .unwrap();

        assert!(encrypted.starts_with(b"manifest-ciphertext:"));
        assert_ne!(
            encrypted,
            TrustlessManifestJsonCodec::encode_manifest(&sample_manifest()).unwrap()
        );

        let decrypted = cipher.decrypt_manifest(&encrypted, &context).unwrap();
        let expected = TrustlessManifestJsonCodec::decode_manifest(
            &TrustlessManifestJsonCodec::encode_manifest(&sample_manifest()).unwrap(),
        )
        .unwrap();

        assert_eq!(decrypted, expected);
    }

    fn entry(object_key_id_byte: u8, object_key: &str) -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key_id: hex::encode([object_key_id_byte; 32]),
            object_key: object_key.to_owned(),
            ciphertext_ref: format!("swarm://ciphertext/{object_key_id_byte}"),
            ciphertext_size: 128,
            content_type: Some("text/plain".to_owned()),
            etag: Some(format!("etag-{object_key_id_byte}")),
        }
    }

    fn sample_manifest() -> TrustlessManifest {
        TrustlessManifest {
            bucket_id: hex::encode([9u8; 32]),
            manifest_version: 7,
            entries: vec![entry(2, "docs/b.txt"), entry(1, "docs/a.txt")],
        }
    }

    #[test]
    fn manifest_json_codec_encodes_manifest_to_deterministic_bytes() {
        let bytes = TrustlessManifestJsonCodec::encode_manifest(&sample_manifest()).unwrap();
        let json = String::from_utf8(bytes).unwrap();

        assert!(json.contains("\"schema\":\"s3w.trustless.manifest\""));
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"manifest_version\":7"));

        let first = json.find(&hex::encode([1u8; 32])).unwrap();
        let second = json.find(&hex::encode([2u8; 32])).unwrap();

        assert!(first < second);
    }

    #[test]
    fn manifest_json_codec_decodes_manifest_from_json_bytes() {
        let bytes = TrustlessManifestJsonCodec::encode_manifest(&sample_manifest()).unwrap();
        let decoded = TrustlessManifestJsonCodec::decode_manifest(&bytes).unwrap();

        assert_eq!(decoded.bucket_id, hex::encode([9u8; 32]));
        assert_eq!(decoded.manifest_version, 7);
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].object_key, "docs/a.txt");
        assert_eq!(decoded.entries[1].object_key, "docs/b.txt");
    }

    #[test]
    fn manifest_json_codec_round_trips_manifest_to_same_canonical_bytes() {
        let bytes = TrustlessManifestJsonCodec::encode_manifest(&sample_manifest()).unwrap();
        let decoded = TrustlessManifestJsonCodec::decode_manifest(&bytes).unwrap();
        let encoded_again = TrustlessManifestJsonCodec::encode_manifest(&decoded).unwrap();

        assert_eq!(bytes, encoded_again);
    }

    #[test]
    fn manifest_json_codec_rejects_empty_json_input() {
        let err = TrustlessManifestJsonCodec::decode_manifest(&[]).unwrap_err();

        assert_eq!(err, TrustlessManifestJsonCodecError::EmptyInput);
    }

    #[test]
    fn manifest_json_codec_rejects_unsupported_schema_version() {
        let json = br#"{"schema":"s3w.trustless.manifest","version":99,"bucket_id":"bucket","manifest_version":1,"entries":[]}"#;

        let err = TrustlessManifestJsonCodec::decode_manifest(json).unwrap_err();

        assert_eq!(
            err,
            TrustlessManifestJsonCodecError::UnsupportedSchemaVersion {
                schema: "s3w.trustless.manifest".to_owned(),
                version: 99,
            }
        );
    }

    #[test]
    fn manifest_json_codec_rejects_duplicate_object_key_ids() {
        let mut manifest = sample_manifest();
        manifest.entries = vec![entry(1, "docs/a.txt"), entry(1, "docs/b.txt")];

        let err = TrustlessManifestJsonCodec::encode_manifest(&manifest).unwrap_err();

        assert_eq!(
            err,
            TrustlessManifestJsonCodecError::DuplicateObjectKeyId(hex::encode([1u8; 32]))
        );
    }

    #[test]
    fn manifest_json_codec_rejects_missing_required_fields() {
        let mut manifest = sample_manifest();
        manifest.bucket_id = " ".to_owned();

        let err = TrustlessManifestJsonCodec::encode_manifest(&manifest).unwrap_err();

        assert_eq!(
            err,
            TrustlessManifestJsonCodecError::Manifest(TrustlessManifestError::MissingBucketId)
        );

        let mut manifest = sample_manifest();
        manifest.entries[0].ciphertext_ref = " ".to_owned();

        let err = TrustlessManifestJsonCodec::encode_manifest(&manifest).unwrap_err();

        assert_eq!(
            err,
            TrustlessManifestJsonCodecError::Manifest(
                TrustlessManifestError::MissingCiphertextReference
            )
        );
    }
}
