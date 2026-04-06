use async_trait::async_trait;
use common::types::{AccessKeyHash, ChainRegistryEntry, SubstrateAddress32};

#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn fetch_entry(
        &self,
        access_key_hash: AccessKeyHash,
    ) -> anyhow::Result<ChainRegistryEntry>;
}

#[async_trait]
pub trait AnchorClient: Send + Sync {
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
