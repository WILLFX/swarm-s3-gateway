use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use common::types::{
    AccessKeyHash, ChainBucketRecord, ChainEncryptionKeyRecord, ChainRegistryEntry,
    SubstrateAddress32,
};
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32, H256},
};
use subxt_signer::sr25519::Keypair;

use crate::{
    contracts_abi::{
        BucketRecord as ContractBucketRecord, EncryptionKeyRecord as ContractEncryptionKeyRecord,
        IdentityRecord as ContractIdentityRecord, decode_query_result, encode_bucket_get_bucket,
        encode_bucket_get_owner_catalog_root, encode_bucket_get_owner_nonce,
        encode_identity_get_encryption_key, encode_identity_get_identity,
    },
    s3_runtime::api,
    traits::RegistryClient,
};

#[derive(Clone)]
pub struct ChainRegistryClient {
    inner: OnlineClient<PolkadotConfig>,
}

impl ChainRegistryClient {
    pub async fn connect(rpc_url: &str) -> Result<Self> {
        let inner = OnlineClient::<PolkadotConfig>::from_url(rpc_url)
            .await
            .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;
        Ok(Self { inner })
    }

    pub fn inner(&self) -> &OnlineClient<PolkadotConfig> {
        &self.inner
    }

    pub async fn get_identity_contract_address(&self) -> Result<Option<SubstrateAddress32>> {
        let at = self
            .inner
            .at_current_block()
            .await
            .context("failed to get current block")?;

        let storage_entry = at
            .storage()
            .entry(api::storage().s3_contracts().identity_contract_address())
            .context("failed to build S3Contracts::IdentityContractAddress storage entry")?;

        let maybe_value = storage_entry
            .try_fetch(())
            .await
            .context("failed to fetch S3Contracts::IdentityContractAddress")?;

        let Some(value) = maybe_value else {
            return Ok(None);
        };

        let address = value
            .decode()
            .context("failed to decode S3Contracts::IdentityContractAddress")?;

        Ok(Some(account_id32_to_array(&address)?))
    }

    pub async fn get_bucket_contract_address(&self) -> Result<Option<SubstrateAddress32>> {
        let at = self
            .inner
            .at_current_block()
            .await
            .context("failed to get current block")?;

        let storage_entry = at
            .storage()
            .entry(api::storage().s3_contracts().bucket_contract_address())
            .context("failed to build S3Contracts::BucketContractAddress storage entry")?;

        let maybe_value = storage_entry
            .try_fetch(())
            .await
            .context("failed to fetch S3Contracts::BucketContractAddress")?;

        let Some(value) = maybe_value else {
            return Ok(None);
        };

        let address = value
            .decode()
            .context("failed to decode S3Contracts::BucketContractAddress")?;

        Ok(Some(account_id32_to_array(&address)?))
    }

    pub async fn get_identity(
        &self,
        access_key_hash: [u8; 32],
    ) -> Result<Option<ChainRegistryEntry>> {
        let contract = self
            .get_identity_contract_address()
            .await?
            .ok_or_else(|| anyhow!("identity contract address is not set in S3Contracts pallet"))?;

        let return_data = self
            .dry_run_contract_read(
                contract,
                encode_identity_get_identity(access_key_hash),
                "identity::get_identity",
            )
            .await?;

        let maybe_entry: Option<ContractIdentityRecord> =
            decode_contract_query(&return_data, "identity::get_identity")?;

        Ok(maybe_entry.map(|entry| ChainRegistryEntry {
            owner: entry.owner,
            encrypted_sigv4_secret: entry.encrypted_sigv4_secret,
            nonce: entry.nonce,
            key_version: entry.key_version,
            enabled: entry.enabled,
        }))
    }

    pub async fn get_encryption_key(
        &self,
        owner: SubstrateAddress32,
    ) -> Result<Option<ChainEncryptionKeyRecord>> {
        let contract = self
            .get_identity_contract_address()
            .await?
            .ok_or_else(|| anyhow!("identity contract address is not set in S3Contracts pallet"))?;

        let return_data = self
            .dry_run_contract_read(
                contract,
                encode_identity_get_encryption_key(owner),
                "identity::get_encryption_key",
            )
            .await?;

        let maybe_record: Option<ContractEncryptionKeyRecord> =
            decode_contract_query(&return_data, "identity::get_encryption_key")?;

        Ok(maybe_record.map(|record| ChainEncryptionKeyRecord {
            owner: record.owner,
            public_key: record.public_key,
            key_type: record.key_type,
            key_version: record.key_version,
            enabled: record.enabled,
            updated_at: record.updated_at,
        }))
    }

    pub async fn get_bucket(
        &self,
        bucket_name_hash: [u8; 32],
    ) -> Result<Option<ChainBucketRecord>> {
        let contract = self
            .get_bucket_contract_address()
            .await?
            .ok_or_else(|| anyhow!("bucket contract address is not set in S3Contracts pallet"))?;

        let return_data = self
            .dry_run_contract_read(
                contract,
                encode_bucket_get_bucket(bucket_name_hash),
                "bucket::get_bucket",
            )
            .await?;

        let maybe_bucket: Option<ContractBucketRecord> =
            decode_contract_query(&return_data, "bucket::get_bucket")?;

        Ok(maybe_bucket.map(|entry| ChainBucketRecord {
            owner: entry.owner,
            is_private: entry.is_private,
            encryption_version: entry.encryption_version,
            creation_date: entry.creation_date,
            bucket_manifest_root: entry.bucket_manifest_root,
        }))
    }

    pub async fn get_owner_catalog_root(&self, owner: SubstrateAddress32) -> Result<Vec<u8>> {
        let contract = self
            .get_bucket_contract_address()
            .await?
            .ok_or_else(|| anyhow!("bucket contract address is not set in S3Contracts pallet"))?;

        let return_data = self
            .dry_run_contract_read(
                contract,
                encode_bucket_get_owner_catalog_root(owner),
                "bucket::get_owner_catalog_root",
            )
            .await?;

        decode_contract_query(&return_data, "bucket::get_owner_catalog_root")
    }

    pub async fn get_owner_nonce(&self, owner: SubstrateAddress32) -> Result<u64> {
        let contract = self
            .get_bucket_contract_address()
            .await?
            .ok_or_else(|| anyhow!("bucket contract address is not set in S3Contracts pallet"))?;

        let return_data = self
            .dry_run_contract_read(
                contract,
                encode_bucket_get_owner_nonce(owner),
                "bucket::get_owner_nonce",
            )
            .await?;

        decode_contract_query(&return_data, "bucket::get_owner_nonce")
    }

    async fn dry_run_contract_read(
        &self,
        dest: SubstrateAddress32,
        input_data: Vec<u8>,
        op_name: &str,
    ) -> Result<Vec<u8>> {
        let latest_block = self
            .inner
            .at_current_block()
            .await
            .with_context(|| format!("failed to access current block for {op_name}"))?;

        let response = latest_block
            .runtime_apis()
            .call(api::runtime_apis().contracts_api().call(
                AccountId32::from([0u8; 32]),
                AccountId32::from(dest),
                0u128,
                None,
                None,
                input_data,
            ))
            .await
            .with_context(|| format!("failed contracts dry-run for {op_name}"))?;

        let exec = response
            .result
            .map_err(|e| anyhow!("contracts dry-run dispatch failed for {op_name}: {:?}", e))?;

        Ok(exec.data)
    }

    pub async fn submit_create_bucket(
        &self,
        owner: SubstrateAddress32,
        bucket_name_hash: [u8; 32],
        is_private: bool,
        signer: &Keypair,
    ) -> Result<H256> {
        let call = api::tx()
            .s3_registry()
            .create_bucket(owner, bucket_name_hash, is_private);

        let mut tx_api = self.inner.tx().await.context("failed to build tx API")?;
        let events = tx_api
            .sign_and_submit_then_watch_default(&call, signer)
            .await
            .context("failed to submit create_bucket extrinsic")?
            .wait_for_finalized_success()
            .await
            .context("create_bucket extrinsic failed before finalization")?;

        Ok(events.extrinsic_hash())
    }

    pub async fn submit_delete_bucket(
        &self,
        bucket_name_hash: [u8; 32],
        signer: &Keypair,
    ) -> Result<H256> {
        let call = api::tx().s3_registry().delete_bucket(bucket_name_hash);

        let mut tx_api = self.inner.tx().await.context("failed to build tx API")?;
        let events = tx_api
            .sign_and_submit_then_watch_default(&call, signer)
            .await
            .context("failed to submit delete_bucket extrinsic")?
            .wait_for_finalized_success()
            .await
            .context("delete_bucket extrinsic failed before finalization")?;

        Ok(events.extrinsic_hash())
    }

    pub async fn submit_increment_encryption_version(
        &self,
        bucket_name_hash: [u8; 32],
        signer: &Keypair,
    ) -> Result<H256> {
        let call = api::tx()
            .s3_registry()
            .increment_encryption_version(bucket_name_hash);

        let mut tx_api = self.inner.tx().await.context("failed to build tx API")?;
        let events = tx_api
            .sign_and_submit_then_watch_default(&call, signer)
            .await
            .context("failed to submit increment_encryption_version extrinsic")?
            .wait_for_finalized_success()
            .await
            .context("increment_encryption_version extrinsic failed before finalization")?;

        Ok(events.extrinsic_hash())
    }
}

#[async_trait]
impl RegistryClient for ChainRegistryClient {
    async fn fetch_entry(
        &self,
        access_key_hash: AccessKeyHash,
    ) -> anyhow::Result<ChainRegistryEntry> {
        self.get_identity(access_key_hash)
            .await?
            .ok_or_else(|| anyhow!("registry entry not found"))
    }

    async fn fetch_bucket(
        &self,
        bucket_name_hash: [u8; 32],
    ) -> anyhow::Result<Option<ChainBucketRecord>> {
        self.get_bucket(bucket_name_hash).await
    }

    async fn fetch_owner_catalog_root(&self, owner: SubstrateAddress32) -> anyhow::Result<Vec<u8>> {
        self.get_owner_catalog_root(owner).await
    }
}

fn decode_contract_query<T: parity_scale_codec::Decode>(
    return_data: &[u8],
    op_name: &str,
) -> Result<T> {
    let decoded = decode_query_result::<T>(return_data)
        .with_context(|| format!("failed to decode return data for {op_name}"))?;

    decoded.map_err(|e| anyhow!("ink query error for {op_name}: {:?}", e))
}

fn account_id32_to_array(account: &AccountId32) -> Result<SubstrateAddress32> {
    let bytes: &[u8] = account.as_ref();
    if bytes.len() != 32 {
        bail!("expected 32-byte AccountId32, got {}", bytes.len());
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
