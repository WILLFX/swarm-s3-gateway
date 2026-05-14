use anyhow::{Context, Result};
use bytes::Bytes;
use common::types::SubstrateAddress32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    bee::client::BeeClient,
    crypto::{
        decrypt_blob, decrypt_bytes, derive_manifest_encryption_key,
        derive_manifest_encryption_nonce, derive_owner_catalog_encryption_key,
        derive_private_bucket_manifest_key, derive_private_object_manifest_key,
        encrypt_blob_random, encrypt_bytes, object_key_hash, private_object_key_id,
    },
};

const OBJECT_MANIFEST_NAMESPACE: &str = "__manifest_object__";
const BUCKET_MANIFEST_NAMESPACE: &str = "__manifest_bucket__";
const ROOT_CATALOG_NAMESPACE: &str = "__manifest_root__";
const ROOT_CATALOG_KEY: &str = "catalog";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectManifest {
    pub swarm_reference: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateObjectManifest {
    pub object_key_hash: [u8; 32],
    pub swarm_reference: String,
    pub encryption_version: u32,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateObjectManifestV2 {
    pub object_key_id: [u8; 32],
    pub encrypted_swarm_reference: String,
    pub encryption_version: u32,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateBucketObjectEntry {
    pub object_key: String,
    pub object_key_id: [u8; 32],
    pub object_manifest_reference: String,
    pub encryption_version: u32,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PrivateBucketManifestV2 {
    pub objects: BTreeMap<String, PrivateBucketObjectEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BucketManifest {
    pub objects: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RootCatalogManifest {
    pub buckets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRecord<T> {
    pub manifest_reference: String,
    pub manifest: T,
}

pub async fn read_owner_catalog_manifest(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    owner_catalog_root: &[u8],
) -> Result<RootCatalogManifest> {
    if owner_catalog_root.is_empty() {
        return Ok(RootCatalogManifest::default());
    }

    if owner_catalog_root.len() != 32 {
        anyhow::bail!(
            "owner_catalog_root must be 32 bytes, got {}",
            owner_catalog_root.len()
        );
    }

    let root_ref = hex::encode(owner_catalog_root);

    let encrypted_bytes = bee
        .get_bytes(&root_ref)
        .await?
        .context("owner catalog root not found in Swarm")?;

    decode_owner_catalog_manifest_bytes(master_key, owner, &root_ref, &encrypted_bytes)
}

fn decode_owner_catalog_manifest_bytes(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    root_ref: &str,
    encrypted_bytes: &[u8],
) -> Result<RootCatalogManifest> {
    let key = derive_owner_catalog_encryption_key(master_key, owner);
    let aad = owner_catalog_aad(owner);

    let plaintext = match decrypt_blob(&key, &aad, encrypted_bytes) {
        Ok(plaintext) => plaintext,
        Err(err) => {
            tracing::warn!(
                owner = %hex::encode(owner),
                root_ref = %root_ref,
                error = %err,
                "owner catalog could not be decrypted; treating as empty legacy/plaintext catalog"
            );

            return Ok(RootCatalogManifest::default());
        }
    };

    serde_json::from_slice(&plaintext).context("failed to deserialize encrypted owner catalog JSON")
}

pub async fn write_owner_catalog_manifest(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    catalog: &RootCatalogManifest,
) -> Result<ManifestRecord<RootCatalogManifest>> {
    let plaintext =
        serde_json::to_vec(catalog).context("failed to serialize owner catalog JSON")?;

    let key = derive_owner_catalog_encryption_key(master_key, owner);
    let aad = owner_catalog_aad(owner);

    let encrypted =
        encrypt_blob_random(&key, &aad, &plaintext).context("failed to encrypt owner catalog")?;

    let put = bee
        .put_bytes(Bytes::from(encrypted))
        .await
        .context("failed to upload encrypted owner catalog bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: catalog.clone(),
    })
}

fn owner_catalog_aad(owner: &SubstrateAddress32) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"s3gw/v1/owner-catalog");
    aad.push(0);
    aad.extend_from_slice(owner);
    aad
}

pub async fn write_private_bucket_manifest_v2(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket: &str,
    encryption_version: u32,
    manifest: &PrivateBucketManifestV2,
) -> Result<ManifestRecord<PrivateBucketManifestV2>> {
    let plaintext =
        serde_json::to_vec(manifest).context("failed to serialize private bucket manifest JSON")?;

    let key = derive_private_bucket_manifest_key(master_key, owner, bucket, encryption_version);
    let aad = private_bucket_manifest_aad(owner, bucket, encryption_version);

    let encrypted = encrypt_blob_random(&key, &aad, &plaintext)
        .context("failed to encrypt private bucket manifest")?;

    let put = bee
        .put_bytes(Bytes::from(encrypted))
        .await
        .context("failed to upload encrypted private bucket manifest bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: manifest.clone(),
    })
}

pub async fn read_private_bucket_manifest_v2(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket: &str,
    encryption_version: u32,
    bucket_manifest_root: &[u8],
) -> Result<Option<ManifestRecord<PrivateBucketManifestV2>>> {
    if bucket_manifest_root.is_empty() {
        return Ok(None);
    }

    if bucket_manifest_root.len() != 32 {
        anyhow::bail!(
            "private bucket_manifest_root must be 32 bytes, got {}",
            bucket_manifest_root.len()
        );
    }

    let manifest_reference = hex::encode(bucket_manifest_root);

    let encrypted_bytes = match bee
        .get_bytes(&manifest_reference)
        .await
        .context("failed to fetch encrypted private bucket manifest bytes")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let key = derive_private_bucket_manifest_key(master_key, owner, bucket, encryption_version);
    let aad = private_bucket_manifest_aad(owner, bucket, encryption_version);

    let plaintext = decrypt_blob(&key, &aad, &encrypted_bytes)
        .context("failed to decrypt private bucket manifest")?;

    let manifest: PrivateBucketManifestV2 = serde_json::from_slice(&plaintext)
        .context("failed to deserialize private bucket manifest JSON")?;

    Ok(Some(ManifestRecord {
        manifest_reference,
        manifest,
    }))
}

pub async fn write_private_object_manifest_v2(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
    manifest: &PrivateObjectManifestV2,
) -> Result<ManifestRecord<PrivateObjectManifestV2>> {
    let plaintext =
        serde_json::to_vec(manifest).context("failed to serialize private object manifest JSON")?;

    let key = derive_private_object_manifest_key(
        master_key,
        owner,
        bucket,
        object_key_id,
        encryption_version,
    );
    let aad = private_object_manifest_aad(owner, bucket, object_key_id, encryption_version);

    let encrypted = encrypt_blob_random(&key, &aad, &plaintext)
        .context("failed to encrypt private object manifest")?;

    let put = bee
        .put_bytes(Bytes::from(encrypted))
        .await
        .context("failed to upload encrypted private object manifest bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: manifest.clone(),
    })
}

pub async fn read_private_object_manifest_v2(
    bee: &BeeClient,
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
    object_manifest_reference: &str,
) -> Result<Option<ManifestRecord<PrivateObjectManifestV2>>> {
    let encrypted_bytes = match bee
        .get_bytes(object_manifest_reference)
        .await
        .context("failed to fetch encrypted private object manifest bytes")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let key = derive_private_object_manifest_key(
        master_key,
        owner,
        bucket,
        object_key_id,
        encryption_version,
    );
    let aad = private_object_manifest_aad(owner, bucket, object_key_id, encryption_version);

    let plaintext = decrypt_blob(&key, &aad, &encrypted_bytes)
        .context("failed to decrypt private object manifest")?;

    let manifest: PrivateObjectManifestV2 = serde_json::from_slice(&plaintext)
        .context("failed to deserialize private object manifest JSON")?;

    Ok(Some(ManifestRecord {
        manifest_reference: object_manifest_reference.to_string(),
        manifest,
    }))
}

pub fn private_object_key_id_hex(private_index_key: &[u8; 32], object_key: &str) -> String {
    hex::encode(private_object_key_id(private_index_key, object_key))
}

fn private_bucket_manifest_aad(
    owner: &SubstrateAddress32,
    bucket: &str,
    encryption_version: u32,
) -> Vec<u8> {
    let normalized_bucket = bucket.to_ascii_lowercase();

    let mut aad = Vec::new();
    aad.extend_from_slice(b"s3gw/v1/private-bucket-manifest");
    aad.push(0);
    aad.extend_from_slice(owner);
    aad.push(0);
    aad.extend_from_slice(normalized_bucket.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&encryption_version.to_le_bytes());
    aad
}

fn private_object_manifest_aad(
    owner: &SubstrateAddress32,
    bucket: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
) -> Vec<u8> {
    let normalized_bucket = bucket.to_ascii_lowercase();

    let mut aad = Vec::new();
    aad.extend_from_slice(b"s3gw/v1/private-object-manifest");
    aad.push(0);
    aad.extend_from_slice(owner);
    aad.push(0);
    aad.extend_from_slice(normalized_bucket.as_bytes());
    aad.push(0);
    aad.extend_from_slice(object_key_id);
    aad.push(0);
    aad.extend_from_slice(&encryption_version.to_le_bytes());
    aad
}

pub async fn write_object_manifest(
    bee: &BeeClient,
    _bucket: &str,
    _key: &str,
    manifest: &ObjectManifest,
) -> Result<ManifestRecord<ObjectManifest>> {
    let payload =
        serde_json::to_vec(manifest).context("failed to serialize object manifest to JSON")?;

    let put = bee
        .put_bytes(Bytes::from(payload))
        .await
        .context("failed to upload object manifest bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: manifest.clone(),
    })
}

pub async fn read_object_manifest(
    bee: &BeeClient,
    bucket: &str,
    key: &str,
) -> Result<Option<ManifestRecord<ObjectManifest>>> {
    let lookup_key = object_manifest_lookup_key(bucket, key);
    let topic = BeeClient::derive_topic(OBJECT_MANIFEST_NAMESPACE, &lookup_key);

    let pointer_bytes = match bee
        .get_pointer_bytes(topic)
        .await
        .context("failed to read object manifest pointer")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    if pointer_bytes.len() != 32 {
        anyhow::bail!(
            "object manifest pointer payload must be 32 bytes, got {}",
            pointer_bytes.len()
        );
    }

    let manifest_reference = hex::encode(&pointer_bytes);

    let manifest_bytes = match bee
        .get_bytes(&manifest_reference)
        .await
        .context("failed to fetch object manifest bytes")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let manifest: ObjectManifest = serde_json::from_slice(&manifest_bytes)
        .context("failed to deserialize object manifest JSON")?;

    Ok(Some(ManifestRecord {
        manifest_reference,
        manifest,
    }))
}

pub async fn write_private_object_manifest(
    bee: &BeeClient,
    master_key: &[u8; 32],
    bucket: &str,
    key: &str,
    encryption_version: u32,
    manifest: &PrivateObjectManifest,
) -> Result<ManifestRecord<PrivateObjectManifest>> {
    let plaintext =
        serde_json::to_vec(manifest).context("failed to serialize private object manifest JSON")?;

    let enc_key = derive_manifest_encryption_key(master_key, bucket, key, encryption_version);
    let enc_nonce = derive_manifest_encryption_nonce(master_key, bucket, key, encryption_version);
    let aad = format!("object-manifest/{bucket}/{key}/{encryption_version}");

    let ciphertext = encrypt_bytes(&enc_key, &enc_nonce, aad.as_bytes(), &plaintext)
        .context("failed to encrypt private object manifest")?;

    let put = bee
        .put_bytes(Bytes::from(ciphertext))
        .await
        .context("failed to upload encrypted private object manifest bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: manifest.clone(),
    })
}

pub async fn read_private_object_manifest(
    bee: &BeeClient,
    master_key: &[u8; 32],
    bucket: &str,
    key: &str,
    encryption_version: u32,
) -> Result<Option<ManifestRecord<PrivateObjectManifest>>> {
    let lookup_key = object_manifest_lookup_key(bucket, key);
    let topic = BeeClient::derive_topic(OBJECT_MANIFEST_NAMESPACE, &lookup_key);

    let pointer_bytes = match bee
        .get_pointer_bytes(topic)
        .await
        .context("failed to read private object manifest pointer")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    if pointer_bytes.len() != 32 {
        anyhow::bail!(
            "private object manifest pointer payload must be 32 bytes, got {}",
            pointer_bytes.len()
        );
    }

    let manifest_reference = hex::encode(&pointer_bytes);

    let manifest_bytes = match bee
        .get_bytes(&manifest_reference)
        .await
        .context("failed to fetch private object manifest bytes")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let enc_key = derive_manifest_encryption_key(master_key, bucket, key, encryption_version);
    let enc_nonce = derive_manifest_encryption_nonce(master_key, bucket, key, encryption_version);
    let aad = format!("object-manifest/{bucket}/{key}/{encryption_version}");

    let plaintext = decrypt_bytes(&enc_key, &enc_nonce, aad.as_bytes(), &manifest_bytes)
        .context("failed to decrypt private object manifest")?;

    let manifest: PrivateObjectManifest = serde_json::from_slice(&plaintext)
        .context("failed to deserialize private object manifest JSON")?;

    Ok(Some(ManifestRecord {
        manifest_reference,
        manifest,
    }))
}

pub async fn write_bucket_manifest(
    bee: &BeeClient,
    _bucket: &str,
    manifest: &BucketManifest,
) -> Result<ManifestRecord<BucketManifest>> {
    let payload =
        serde_json::to_vec(manifest).context("failed to serialize bucket manifest to JSON")?;

    let put = bee
        .put_bytes(Bytes::from(payload))
        .await
        .context("failed to upload bucket manifest bytes to Bee")?;

    Ok(ManifestRecord {
        manifest_reference: put.reference,
        manifest: manifest.clone(),
    })
}

pub async fn read_bucket_manifest(
    bee: &BeeClient,
    bucket: &str,
) -> Result<Option<ManifestRecord<BucketManifest>>> {
    let topic = BeeClient::derive_topic(BUCKET_MANIFEST_NAMESPACE, bucket);

    let pointer_bytes = match bee
        .get_pointer_bytes(topic)
        .await
        .context("failed to read bucket manifest pointer")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    if pointer_bytes.len() != 32 {
        anyhow::bail!(
            "bucket manifest pointer payload must be 32 bytes, got {}",
            pointer_bytes.len()
        );
    }

    let manifest_reference = hex::encode(&pointer_bytes);

    let manifest_bytes = match bee
        .get_bytes(&manifest_reference)
        .await
        .context("failed to fetch bucket manifest bytes")?
    {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let manifest: BucketManifest = serde_json::from_slice(&manifest_bytes)
        .context("failed to deserialize bucket manifest JSON")?;

    Ok(Some(ManifestRecord {
        manifest_reference,
        manifest,
    }))
}

pub fn root_catalog_lookup_key() -> (&'static str, &'static str) {
    (ROOT_CATALOG_NAMESPACE, ROOT_CATALOG_KEY)
}

fn object_manifest_lookup_key(bucket: &str, key: &str) -> String {
    format!("{bucket}/{key}")
}

pub fn build_private_object_manifest(
    object_key: &str,
    swarm_reference: String,
    encryption_version: u32,
    size: u64,
    etag: String,
    content_type: String,
    last_modified: String,
) -> PrivateObjectManifest {
    PrivateObjectManifest {
        object_key_hash: object_key_hash(object_key),
        swarm_reference,
        encryption_version,
        size,
        etag,
        content_type,
        last_modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_catalog_decrypt_failure_falls_back_to_empty_catalog() {
        let master_key = [7u8; 32];
        let owner = [9u8; 32];

        let legacy_plaintext_or_invalid_bytes = br#"{"buckets":{"old-bucket":"plaintext-ref"}}"#;

        let catalog = decode_owner_catalog_manifest_bytes(
            &master_key,
            &owner,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            legacy_plaintext_or_invalid_bytes,
        )
        .unwrap();

        assert!(
            catalog.buckets.is_empty(),
            "legacy/plaintext owner catalog bytes must be treated as empty on decrypt failure"
        );
    }

    #[test]
    fn encrypted_owner_catalog_decodes_successfully() {
        let master_key = [7u8; 32];
        let owner = [9u8; 32];

        let mut expected = RootCatalogManifest::default();
        expected.buckets.insert(
            "private-bucket".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );

        let plaintext = serde_json::to_vec(&expected).unwrap();

        let key = derive_owner_catalog_encryption_key(&master_key, &owner);
        let aad = owner_catalog_aad(&owner);
        let encrypted = encrypt_blob_random(&key, &aad, &plaintext).unwrap();

        let decoded = decode_owner_catalog_manifest_bytes(
            &master_key,
            &owner,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &encrypted,
        )
        .unwrap();

        assert_eq!(decoded, expected);
    }
}
