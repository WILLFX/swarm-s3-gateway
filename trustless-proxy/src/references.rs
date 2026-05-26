use thiserror::Error;

use crate::manifest::TrustlessManifestEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessObjectReferenceInput {
    pub bucket_id: String,
    pub object_key: String,
    pub object_key_id: String,
    pub ciphertext_ref: String,
    pub ciphertext_size: u64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessObjectReference {
    pub bucket_id: String,
    pub object_key: String,
    pub object_key_id: String,
    pub ciphertext_ref: String,
    pub ciphertext_size: u64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
    pub plaintext_key_stays_local: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustlessRemoteObjectReference {
    pub bucket_id: String,
    pub object_key_id: String,
    pub ciphertext_ref: String,
    pub ciphertext_size: u64,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedManifestReference {
    pub bucket_id: String,
    pub manifest_ref: String,
    pub manifest_version: u64,
    pub encrypted_manifest_only: bool,
    pub gateway_plaintext_access: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustlessReferenceError {
    #[error("bucket id is required")]
    MissingBucketId,

    #[error("object key is required")]
    MissingObjectKey,

    #[error("object key id is required")]
    MissingObjectKeyId,

    #[error("ciphertext reference is required")]
    MissingCiphertextReference,

    #[error("ciphertext size must be greater than zero")]
    MissingCiphertextSize,

    #[error("encrypted manifest reference is required")]
    MissingEncryptedManifestReference,

    #[error("gateway plaintext access is not allowed for trustless references")]
    GatewayPlaintextAccessRejected,
}

pub struct TrustlessReferenceModel;

impl TrustlessReferenceModel {
    pub fn object_reference(
        input: TrustlessObjectReferenceInput,
    ) -> Result<TrustlessObjectReference, TrustlessReferenceError> {
        let bucket_id =
            require_non_empty(input.bucket_id, TrustlessReferenceError::MissingBucketId)?;
        let object_key =
            require_non_empty(input.object_key, TrustlessReferenceError::MissingObjectKey)?;
        let object_key_id = require_non_empty(
            input.object_key_id,
            TrustlessReferenceError::MissingObjectKeyId,
        )?;
        let ciphertext_ref = require_non_empty(
            input.ciphertext_ref,
            TrustlessReferenceError::MissingCiphertextReference,
        )?;

        if input.ciphertext_size == 0 {
            return Err(TrustlessReferenceError::MissingCiphertextSize);
        }

        Ok(TrustlessObjectReference {
            bucket_id,
            object_key,
            object_key_id,
            ciphertext_ref,
            ciphertext_size: input.ciphertext_size,
            content_type: normalize_optional(input.content_type),
            etag: normalize_optional(input.etag),
            plaintext_key_stays_local: true,
            gateway_plaintext_access: false,
        })
    }

    pub fn remote_object_reference(
        reference: &TrustlessObjectReference,
    ) -> Result<TrustlessRemoteObjectReference, TrustlessReferenceError> {
        if reference.gateway_plaintext_access || !reference.plaintext_key_stays_local {
            return Err(TrustlessReferenceError::GatewayPlaintextAccessRejected);
        }

        Ok(TrustlessRemoteObjectReference {
            bucket_id: reference.bucket_id.clone(),
            object_key_id: reference.object_key_id.clone(),
            ciphertext_ref: reference.ciphertext_ref.clone(),
            ciphertext_size: reference.ciphertext_size,
            gateway_plaintext_access: false,
        })
    }

    pub fn manifest_entry(reference: &TrustlessObjectReference) -> TrustlessManifestEntry {
        TrustlessManifestEntry {
            object_key: reference.object_key.clone(),
            object_key_id: reference.object_key_id.clone(),
            ciphertext_ref: reference.ciphertext_ref.clone(),
            ciphertext_size: reference.ciphertext_size,
            content_type: reference.content_type.clone(),
            etag: reference.etag.clone(),
        }
    }

    pub fn object_reference_from_manifest_entry(
        bucket_id: impl Into<String>,
        entry: TrustlessManifestEntry,
    ) -> Result<TrustlessObjectReference, TrustlessReferenceError> {
        Self::object_reference(TrustlessObjectReferenceInput {
            bucket_id: bucket_id.into(),
            object_key: entry.object_key,
            object_key_id: entry.object_key_id,
            ciphertext_ref: entry.ciphertext_ref,
            ciphertext_size: entry.ciphertext_size,
            content_type: entry.content_type,
            etag: entry.etag,
        })
    }

    pub fn encrypted_manifest_reference(
        bucket_id: impl Into<String>,
        manifest_ref: impl Into<String>,
        manifest_version: u64,
    ) -> Result<EncryptedManifestReference, TrustlessReferenceError> {
        let bucket_id =
            require_non_empty(bucket_id.into(), TrustlessReferenceError::MissingBucketId)?;
        let manifest_ref = require_non_empty(
            manifest_ref.into(),
            TrustlessReferenceError::MissingEncryptedManifestReference,
        )?;

        Ok(EncryptedManifestReference {
            bucket_id,
            manifest_ref,
            manifest_version,
            encrypted_manifest_only: true,
            gateway_plaintext_access: false,
        })
    }
}

fn require_non_empty(
    value: String,
    error: TrustlessReferenceError,
) -> Result<String, TrustlessReferenceError> {
    let value = value.trim().to_owned();

    if value.is_empty() {
        return Err(error);
    }

    Ok(value)
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> TrustlessObjectReferenceInput {
        TrustlessObjectReferenceInput {
            bucket_id: hex::encode([1u8; 32]),
            object_key: "docs/private.txt".to_owned(),
            object_key_id: hex::encode([2u8; 32]),
            ciphertext_ref: "swarm://ciphertext/ref".to_owned(),
            ciphertext_size: 128,
            content_type: Some(" text/plain ".to_owned()),
            etag: Some(" etag-1 ".to_owned()),
        }
    }

    #[test]
    fn object_reference_keeps_plaintext_key_local_and_gateway_ciphertext_only() {
        let reference = TrustlessReferenceModel::object_reference(input()).unwrap();

        assert_eq!(reference.object_key, "docs/private.txt");
        assert!(reference.plaintext_key_stays_local);
        assert!(!reference.gateway_plaintext_access);
        assert_eq!(reference.content_type, Some("text/plain".to_owned()));
        assert_eq!(reference.etag, Some("etag-1".to_owned()));
    }

    #[test]
    fn remote_object_reference_excludes_plaintext_object_key() {
        let reference = TrustlessReferenceModel::object_reference(input()).unwrap();

        let remote = TrustlessReferenceModel::remote_object_reference(&reference).unwrap();

        assert_eq!(remote.bucket_id, reference.bucket_id);
        assert_eq!(remote.object_key_id, reference.object_key_id);
        assert_eq!(remote.ciphertext_ref, reference.ciphertext_ref);
        assert!(!remote.gateway_plaintext_access);
    }

    #[test]
    fn manifest_entry_roundtrip_preserves_local_metadata() {
        let reference = TrustlessReferenceModel::object_reference(input()).unwrap();

        let entry = TrustlessReferenceModel::manifest_entry(&reference);
        let roundtrip = TrustlessReferenceModel::object_reference_from_manifest_entry(
            reference.bucket_id.clone(),
            entry,
        )
        .unwrap();

        assert_eq!(roundtrip.object_key, reference.object_key);
        assert_eq!(roundtrip.object_key_id, reference.object_key_id);
        assert_eq!(roundtrip.ciphertext_ref, reference.ciphertext_ref);
        assert!(roundtrip.plaintext_key_stays_local);
        assert!(!roundtrip.gateway_plaintext_access);
    }

    #[test]
    fn encrypted_manifest_reference_is_encrypted_only() {
        let reference = TrustlessReferenceModel::encrypted_manifest_reference(
            hex::encode([1u8; 32]),
            "swarm://encrypted-manifest/root",
            9,
        )
        .unwrap();

        assert_eq!(reference.manifest_version, 9);
        assert!(reference.encrypted_manifest_only);
        assert!(!reference.gateway_plaintext_access);
    }

    #[test]
    fn reference_model_rejects_missing_fields_and_empty_ciphertext() {
        assert_eq!(
            TrustlessReferenceModel::object_reference(TrustlessObjectReferenceInput {
                bucket_id: " ".to_owned(),
                ..input()
            })
            .unwrap_err(),
            TrustlessReferenceError::MissingBucketId
        );

        assert_eq!(
            TrustlessReferenceModel::object_reference(TrustlessObjectReferenceInput {
                object_key: " ".to_owned(),
                ..input()
            })
            .unwrap_err(),
            TrustlessReferenceError::MissingObjectKey
        );

        assert_eq!(
            TrustlessReferenceModel::object_reference(TrustlessObjectReferenceInput {
                object_key_id: " ".to_owned(),
                ..input()
            })
            .unwrap_err(),
            TrustlessReferenceError::MissingObjectKeyId
        );

        assert_eq!(
            TrustlessReferenceModel::object_reference(TrustlessObjectReferenceInput {
                ciphertext_ref: " ".to_owned(),
                ..input()
            })
            .unwrap_err(),
            TrustlessReferenceError::MissingCiphertextReference
        );

        assert_eq!(
            TrustlessReferenceModel::object_reference(TrustlessObjectReferenceInput {
                ciphertext_size: 0,
                ..input()
            })
            .unwrap_err(),
            TrustlessReferenceError::MissingCiphertextSize
        );
    }

    #[test]
    fn reference_model_rejects_gateway_plaintext_access() {
        let mut reference = TrustlessReferenceModel::object_reference(input()).unwrap();
        reference.gateway_plaintext_access = true;

        assert_eq!(
            TrustlessReferenceModel::remote_object_reference(&reference).unwrap_err(),
            TrustlessReferenceError::GatewayPlaintextAccessRejected
        );

        let mut reference = TrustlessReferenceModel::object_reference(input()).unwrap();
        reference.plaintext_key_stays_local = false;

        assert_eq!(
            TrustlessReferenceModel::remote_object_reference(&reference).unwrap_err(),
            TrustlessReferenceError::GatewayPlaintextAccessRejected
        );
    }
}
