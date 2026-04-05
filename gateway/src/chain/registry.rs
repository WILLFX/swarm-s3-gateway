use anyhow::{anyhow, Result};
use async_trait::async_trait;
use subxt::OnlineClient;
use subxt::PolkadotConfig;

#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn fetch_entry(&self, access_key_hash: [u8; 32]) -> Result<ChainRegistryEntry>;
}

pub struct SubxtRegistryClient {
    pub api: OnlineClient<PolkadotConfig>,
}

#[async_trait]
impl RegistryClient for SubxtRegistryClient {
    async fn fetch_entry(&self, access_key_hash: [u8; 32]) -> Result<ChainRegistryEntry> {
        // Assuming subxt codegen generated `runtime` module.
        let storage = runtime::storage().registry().credentials(access_key_hash);

        let maybe = self
            .api
            .storage()
            .at_latest()
            .await?
            .fetch(&storage)
            .await?;

        let entry = maybe.ok_or_else(|| anyhow!("registry entry not found"))?;
        if !entry.enabled {
            return Err(anyhow!("credential disabled"));
        }

        Ok(ChainRegistryEntry {
            owner: entry.owner.0,
            encrypted_sigv4_secret: entry.encrypted_sigv4_secret.0,
            nonce: entry.nonce.0,
            key_version: entry.key_version,
            enabled: entry.enabled,
        })
    }
}﻿
