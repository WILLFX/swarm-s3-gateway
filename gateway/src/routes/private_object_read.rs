use anyhow::{Context, Result};
use common::types::{ChainBucketRecord, SubstrateAddress32};

use crate::{
    app_state::{AppState, ObjectMetadata},
    crypto::{derive_private_object_index_key, private_object_key_id},
    manifest::{
        PrivateBucketObjectEntry, PrivateObjectManifestV2, read_private_bucket_manifest_v2,
        read_private_object_manifest_v2,
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

    let Some(entry) = bucket_manifest
        .objects
        .values()
        .find(|entry| entry.object_key == key)
        .cloned()
    else {
        return Ok(None);
    };

    let private_index_key = derive_private_object_index_key(
        &state.master_service_key,
        owner,
        bucket,
        entry.encryption_version,
    );

    let expected_object_key_id = private_object_key_id(&private_index_key, key);

    if entry.object_key_id != expected_object_key_id {
        anyhow::bail!("private bucket manifest object_key_id mismatch for stored object key");
    }

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
