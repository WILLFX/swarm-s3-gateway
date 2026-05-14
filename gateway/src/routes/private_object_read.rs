use anyhow::{Context, Result};
use common::types::{ChainBucketRecord, SubstrateAddress32};

use crate::{
    app_state::{AppState, ObjectMetadata},
    crypto::{derive_private_object_index_key, private_object_key_id},
    manifest::{
        PrivateBucketManifestV2, PrivateBucketObjectEntry, PrivateObjectManifestV2,
        read_private_bucket_manifest_v2, read_private_object_manifest_v2,
    },
};

#[derive(Debug, Clone)]
pub struct PrivateResolvedObject {
    pub object_key_id: [u8; 32],
    pub bucket_entry: PrivateBucketObjectEntry,
    pub object_manifest: PrivateObjectManifestV2,
}

impl PrivateResolvedObject {
    pub fn metadata(&self) -> ObjectMetadata {
        ObjectMetadata {
            swarm_reference: self.object_manifest.encrypted_swarm_reference.clone(),
            size: self.object_manifest.size,
            etag: self.object_manifest.etag.clone(),
            content_type: self.object_manifest.content_type.clone(),
            last_modified: self.object_manifest.last_modified.clone(),
            is_private: true,
            encryption_version: Some(self.object_manifest.encryption_version),
        }
    }
}

pub async fn resolve_private_object_from_bucket(
    state: &AppState,
    owner: &SubstrateAddress32,
    bucket: &str,
    key: &str,
    chain_bucket: &ChainBucketRecord,
) -> Result<Option<PrivateResolvedObject>> {
    if chain_bucket.bucket_manifest_root.is_empty() {
        return Ok(None);
    }

    let bucket_manifest = match read_private_bucket_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        owner,
        bucket,
        chain_bucket.encryption_version,
        &chain_bucket.bucket_manifest_root,
    )
    .await?
    {
        Some(record) => record.manifest,
        None => return Ok(None),
    };

    let Some(entry) = find_private_bucket_entry_for_key(
        &state.master_service_key,
        owner,
        bucket,
        key,
        &bucket_manifest,
    )?
    else {
        return Ok(None);
    };

    let object_record = match read_private_object_manifest_v2(
        state.bee_client.as_ref(),
        &state.master_service_key,
        owner,
        bucket,
        &entry.object_key_id,
        entry.encryption_version,
        &entry.object_manifest_reference,
    )
    .await
    .with_context(|| format!("failed to read private object manifest for key {key}"))?
    {
        Some(record) => record,
        None => return Ok(None),
    };

    if object_record.manifest.object_key_id != entry.object_key_id {
        anyhow::bail!("private object manifest object_key_id mismatch");
    }

    if object_record.manifest.encryption_version != entry.encryption_version {
        anyhow::bail!("private object manifest encryption_version mismatch");
    }

    Ok(Some(PrivateResolvedObject {
        object_key_id: entry.object_key_id,
        bucket_entry: entry,
        object_manifest: object_record.manifest,
    }))
}

fn find_private_bucket_entry_for_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket: &str,
    key: &str,
    bucket_manifest: &PrivateBucketManifestV2,
) -> Result<Option<PrivateBucketObjectEntry>> {
    let Some(entry) = bucket_manifest
        .objects
        .values()
        .find(|entry| entry.object_key == key)
        .cloned()
    else {
        return Ok(None);
    };

    let private_index_key =
        derive_private_object_index_key(master_key, owner, bucket, entry.encryption_version);

    let expected_object_key_id = private_object_key_id(&private_index_key, key);

    if entry.object_key_id != expected_object_key_id {
        anyhow::bail!("private bucket manifest object_key_id mismatch for stored object key");
    }

    Ok(Some(entry))
}

pub fn private_object_payload_aad(
    owner: &SubstrateAddress32,
    bucket: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
) -> Vec<u8> {
    let normalized_bucket = bucket.to_ascii_lowercase();

    let mut aad = Vec::new();
    aad.extend_from_slice(b"s3gw/v1/private-object-payload");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn entry_for_version(
        master_key: &[u8; 32],
        owner: &SubstrateAddress32,
        bucket: &str,
        object_key: &str,
        encryption_version: u32,
    ) -> PrivateBucketObjectEntry {
        let index_key =
            derive_private_object_index_key(master_key, owner, bucket, encryption_version);
        let object_key_id = private_object_key_id(&index_key, object_key);

        PrivateBucketObjectEntry {
            object_key: object_key.to_string(),
            object_key_id,
            object_manifest_reference:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            encryption_version,
            size: 38,
            etag: "etag".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-05-14T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn private_entry_lookup_uses_entry_encryption_version() {
        let master_key = [7u8; 32];
        let owner = [9u8; 32];
        let bucket = "test-bucket-private";
        let object_key = "secret.txt";

        let entry_version = 1u32;
        let current_bucket_version = 7u32;

        let entry = entry_for_version(&master_key, &owner, bucket, object_key, entry_version);

        let current_index_key =
            derive_private_object_index_key(&master_key, &owner, bucket, current_bucket_version);
        let current_version_object_key_id = private_object_key_id(&current_index_key, object_key);

        assert_ne!(
            entry.object_key_id, current_version_object_key_id,
            "test setup must prove current bucket version would derive a different object id"
        );

        let mut objects = BTreeMap::new();
        objects.insert(hex::encode(entry.object_key_id), entry.clone());

        let manifest = PrivateBucketManifestV2 { objects };

        let resolved =
            find_private_bucket_entry_for_key(&master_key, &owner, bucket, object_key, &manifest)
                .unwrap()
                .expect("entry should resolve by stored object_key");

        assert_eq!(resolved.object_key_id, entry.object_key_id);
        assert_eq!(resolved.encryption_version, entry_version);
    }

    #[test]
    fn private_entry_lookup_returns_none_for_missing_key() {
        let master_key = [7u8; 32];
        let owner = [9u8; 32];
        let bucket = "test-bucket-private";

        let entry = entry_for_version(&master_key, &owner, bucket, "secret.txt", 1);

        let mut objects = BTreeMap::new();
        objects.insert(hex::encode(entry.object_key_id), entry);

        let manifest = PrivateBucketManifestV2 { objects };

        let resolved = find_private_bucket_entry_for_key(
            &master_key,
            &owner,
            bucket,
            "missing.txt",
            &manifest,
        )
        .unwrap();

        assert!(resolved.is_none());
    }

    #[test]
    fn private_entry_lookup_rejects_object_key_id_mismatch() {
        let master_key = [7u8; 32];
        let owner = [9u8; 32];
        let bucket = "test-bucket-private";
        let object_key = "secret.txt";

        let mut entry = entry_for_version(&master_key, &owner, bucket, object_key, 1);
        entry.object_key_id = [0u8; 32];

        let mut objects = BTreeMap::new();
        objects.insert(hex::encode(entry.object_key_id), entry);

        let manifest = PrivateBucketManifestV2 { objects };

        let err =
            find_private_bucket_entry_for_key(&master_key, &owner, bucket, object_key, &manifest)
                .unwrap_err();

        assert!(
            err.to_string().contains("object_key_id mismatch"),
            "unexpected error: {err}"
        );
    }
}
