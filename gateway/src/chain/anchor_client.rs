use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use common::types::SubstrateAddress32;
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32 as SubxtAccountId32, MultiAddress},
};
use subxt_signer::sr25519::Keypair;
use tracing::debug;

use crate::{
    contracts_abi::{
        BucketError, decode_exec_result, encode_bucket_create_bucket_cas,
        encode_bucket_delete_bucket_cas, encode_bucket_update_bucket_manifest_root_for_delete_cas,
        encode_bucket_update_bucket_manifest_root_for_put_cas,
    },
    s3_runtime::api,
    traits::AnchorClient,
};

pub struct ContractAnchorClient {
    inner: OnlineClient<PolkadotConfig>,
    bucket_contract: SubstrateAddress32,
    signer: Keypair,
    caller: SubstrateAddress32,
}

impl ContractAnchorClient {
    pub fn new(
        inner: OnlineClient<PolkadotConfig>,
        bucket_contract: SubstrateAddress32,
        signer: Keypair,
        caller: SubstrateAddress32,
    ) -> Self {
        Self {
            inner,
            bucket_contract,
            signer,
            caller,
        }
    }

    async fn submit_bucket_contract_call(
        &self,
        input_data: Vec<u8>,
        op_name: &'static str,
    ) -> Result<String> {
        let origin = SubxtAccountId32::from(self.caller);
        let dest = SubxtAccountId32::from(self.bucket_contract);

        let latest_block = self
            .inner
            .at_current_block()
            .await
            .with_context(|| format!("failed to access current block for {op_name}"))?;

        let dry_run = latest_block
            .runtime_apis()
            .call(api::runtime_apis().contracts_api().call(
                origin,
                dest.clone(),
                0u128,
                None,
                None,
                input_data.clone(),
            ))
            .await
            .with_context(|| format!("contracts dry-run failed for {op_name}"))?;

        debug!(op_name, gas_required = ?dry_run.gas_required, "contract dry-run completed");

        if !dry_run.debug_message.is_empty() {
            debug!(
                op_name,
                debug_message = %String::from_utf8_lossy(&dry_run.debug_message),
                "contract dry-run debug message"
            );
        }

        let exec = dry_run
            .result
            .map_err(|err| anyhow!("contracts dry-run dispatch failed for {op_name}: {err:?}"))?;

        let decoded = decode_exec_result::<(), BucketError>(&exec.data)
            .with_context(|| format!("failed to decode contract execution result for {op_name}"))?;

        decoded
            .map_err(|err| anyhow!("ink dispatch error for {op_name}: {err:?}"))?
            .map_err(|err| anyhow!("bucket contract error for {op_name}: {err:?}"))?;

        let call = api::tx().contracts().call(
            MultiAddress::Id(dest),
            0u128,
            dry_run.gas_required,
            None,
            input_data,
        );

        let mut tx_api = self.inner.tx().await.context("failed to build tx API")?;

        let events = tx_api
            .sign_and_submit_then_watch_default(&call, &self.signer)
            .await
            .with_context(|| format!("failed to submit contract call for {op_name}"))?
            .wait_for_finalized_success()
            .await
            .with_context(|| format!("{op_name} failed before finalization"))?;

        Ok(events.extrinsic_hash().to_string())
    }
}

#[async_trait]
impl AnchorClient for ContractAnchorClient {
    async fn create_bucket_anchor(
        &self,
        owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        is_private: bool,
        owner_signature: [u8; 64],
        expected_owner_catalog_root: String,
        owner_catalog_root: String,
    ) -> Result<String> {
        let expected_owner_catalog_root =
            decode_swarm_reference_or_empty(&expected_owner_catalog_root)?;
        let owner_catalog_root = decode_swarm_reference_or_empty(&owner_catalog_root)?;

        let input_data = encode_bucket_create_bucket_cas(
            owner,
            bucket_id,
            is_private,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        );

        self.submit_bucket_contract_call(input_data, "bucket::create_bucket_cas")
            .await
    }

    async fn delete_bucket_anchor(
        &self,
        bucket_id: [u8; 32],
        owner_signature: [u8; 64],
        expected_owner_catalog_root: String,
        owner_catalog_root: String,
    ) -> Result<String> {
        let expected_owner_catalog_root =
            decode_swarm_reference_or_empty(&expected_owner_catalog_root)?;
        let owner_catalog_root = decode_swarm_reference_or_empty(&owner_catalog_root)?;

        let input_data = encode_bucket_delete_bucket_cas(
            bucket_id,
            owner_signature,
            expected_owner_catalog_root,
            owner_catalog_root,
        );

        self.submit_bucket_contract_call(input_data, "bucket::delete_bucket_cas")
            .await
    }

    async fn update_bucket_manifest_root_for_put_anchor(
        &self,
        bucket_id: [u8; 32],
        expected_bucket_manifest_root: String,
        bucket_manifest_root: String,
    ) -> Result<String> {
        let expected_bucket_manifest_root =
            decode_swarm_reference_or_empty(&expected_bucket_manifest_root)?;
        let bucket_manifest_root = decode_swarm_reference(&bucket_manifest_root)?;

        let input_data = encode_bucket_update_bucket_manifest_root_for_put_cas(
            bucket_id,
            expected_bucket_manifest_root,
            bucket_manifest_root,
        );

        self.submit_bucket_contract_call(
            input_data,
            "bucket::update_bucket_manifest_root_for_put_cas",
        )
        .await
    }

    async fn update_bucket_manifest_root_for_delete_anchor(
        &self,
        bucket_id: [u8; 32],
        expected_bucket_manifest_root: String,
        bucket_manifest_root: String,
    ) -> Result<String> {
        let expected_bucket_manifest_root =
            decode_swarm_reference_or_empty(&expected_bucket_manifest_root)?;
        let bucket_manifest_root = decode_swarm_reference(&bucket_manifest_root)?;

        let input_data = encode_bucket_update_bucket_manifest_root_for_delete_cas(
            bucket_id,
            expected_bucket_manifest_root,
            bucket_manifest_root,
        );

        self.submit_bucket_contract_call(
            input_data,
            "bucket::update_bucket_manifest_root_for_delete_cas",
        )
        .await
    }

    async fn submit_anchor_object(
        &self,
        _owner: SubstrateAddress32,
        bucket_id: [u8; 32],
        _object_key_id: [u8; 32],
        _swarm_ref: String,
        expected_bucket_manifest_root: String,
        bucket_manifest_root: String,
        _size: u64,
        _etag: [u8; 32],
    ) -> Result<String> {
        self.update_bucket_manifest_root_for_put_anchor(
            bucket_id,
            expected_bucket_manifest_root,
            bucket_manifest_root,
        )
        .await
    }
}

fn decode_swarm_reference_or_empty(value: &str) -> Result<Vec<u8>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }

    decode_swarm_reference(value)
}

fn decode_swarm_reference(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim().trim_start_matches("0x");

    let bytes = hex::decode(trimmed).with_context(|| {
        format!("bucket manifest root must be a hex Swarm reference, got {value}")
    })?;

    if bytes.len() != 32 {
        bail!(
            "bucket manifest root must decode to 32 bytes, got {}",
            bytes.len()
        );
    }

    Ok(bytes)
}
