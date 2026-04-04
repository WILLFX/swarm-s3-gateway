use crate::traits::RegistryClient;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::types::{AccessKeyHash, ChainRegistryEntry};
use parity_scale_codec::Decode;
use subxt::{
    dynamic::{self, Value},
    utils::AccountId32,
    OnlineClient, PolkadotConfig,
};

#[derive(Clone)]
pub struct SubxtRegistryClient {
    pub api: OnlineClient<PolkadotConfig>,
    /// Runtime pallet name, e.g. "Registry"
    pub pallet_name: &'static str,
    /// Storage item name, e.g. "Credentials"
    pub storage_name: &'static str,
}

impl SubxtRegistryClient {
    pub fn new(api: OnlineClient<PolkadotConfig>) -> Self {
        Self {
            api,
            pallet_name: "Registry",
            storage_name: "Credentials",
        }
    }
}

#[derive(Debug, Clone, Decode)]
struct RegistryEntryScale {
    owner: AccountId32,
    encrypted_sigv4_secret: Vec<u8>,
    nonce: Vec<u8>,
    key_version: u32,
    enabled: bool,
}

#[async_trait]
impl RegistryClient for SubxtRegistryClient {
    async fn fetch_entry(&self, access_key_hash: AccessKeyHash) -> Result<ChainRegistryEntry> {
        let storage_addr = dynamic::storage(
            self.pallet_name,
            self.storage_name,
            vec![Value::from_bytes(access_key_hash.to_vec())],
        );

        // Non-blocking async chain query
        let at = self.api.storage().at_latest().await?;
        let maybe = at.fetch(&storage_addr).await?;

        let raw = maybe.ok_or_else(|| anyhow!("registry entry not found"))?;
        let decoded: RegistryEntryScale = raw
            .as_type()
            .context("failed to decode registry entry from chain")?;

        if !decoded.enabled {
            return Err(anyhow!("credential disabled"));
        }

        Ok(ChainRegistryEntry {
            owner: decoded.owner.0,
            encrypted_sigv4_secret: decoded.encrypted_sigv4_secret,
            nonce: decoded.nonce,
            key_version: decoded.key_version,
            enabled: decoded.enabled,
        })
    }
}
