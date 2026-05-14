use async_trait::async_trait;
use common::types::{AccessKeyHash, ChainBucketRecord, ChainRegistryEntry, SubstrateAddress32};

#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn fetch_entry(
        &self,
        access_key_hash: AccessKeyHash,
    ) -> anyhow::Result<ChainRegistryEntry>;

    async fn fetch_bucket(
        &self,
        bucket_name_hash: [u8; 32],
    ) -> anyhow::Result<Option<ChainBucketRecord>>;

    async fn fetch_owner_catalog_root(&self, owner: SubstrateAddress32) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
pub trait AnchorClient: Send + Sync {
    async fn create_bucket_anchor(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        is_private: bool,
        owner_signature: [u8; 64],
        owner_catalog_root: String,
    ) -> anyhow::Result<String>;

    async fn delete_bucket_anchor(
        &self,
        bucket_id: [u8; 32],
        owner_signature: [u8; 64],
        owner_catalog_root: String,
    ) -> anyhow::Result<String>;

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        bucket_id: [u8; 32],
        bucket_manifest_root: String,
    ) -> anyhow::Result<String>;

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        bucket_id: [u8; 32],
        bucket_manifest_root: String,
    ) -> anyhow::Result<String>;

    async fn submit_anchor_object(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        object_key_id: [u8; 32],
        swarm_ref: String,
        bucket_manifest_root: String,
        size: u64,
        etag: [u8; 32],
    ) -> anyhow::Result<String>;
}

#[async_trait]
pub trait SecretUnwrapper: Send + Sync {
    async fn unwrap_sigv4_secret(
        &self,
        key_version: u32,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}
