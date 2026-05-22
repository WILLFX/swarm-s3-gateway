use anyhow::{Context, Result, anyhow, bail};
use gateway::{
    chain::registry::ChainRegistryClient,
    contracts_abi::{IdentityError, decode_exec_result, encode_identity_grant_delegation},
    s3_runtime::api,
};
use std::{env, str::FromStr};
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32, MultiAddress},
};
use subxt_signer::{SecretUri, sr25519::Keypair};

const ALICE_OWNER_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);

    let delegate_hex = args.next().ok_or_else(|| {
        anyhow!("usage: grant_delegation <delegate_hex> <allowed_operations> <expires_at>")
    })?;
    let allowed_operations = args
        .next()
        .ok_or_else(|| anyhow!("missing allowed_operations"))?
        .parse::<u32>()
        .context("allowed_operations must be u32")?;
    let expires_at = args
        .next()
        .ok_or_else(|| anyhow!("missing expires_at"))?
        .parse::<u64>()
        .context("expires_at must be u64")?;

    if args.next().is_some() {
        bail!("too many arguments");
    }

    let rpc_url = required_env("RPC_URL")?;
    let owner_hex = env::var("OWNER_HEX").unwrap_or_else(|_| ALICE_OWNER_HEX.to_string());

    let owner = decode_32_hex(&owner_hex, "OWNER_HEX")?;
    let delegate = decode_32_hex(&delegate_hex, "delegate_hex")?;

    let signer = load_owner_signer()?;
    let signer_account = signer.public_key().0;

    if signer_account != owner {
        bail!("OWNER_HEX must match the public key derived from S3GW_DELEGATION_OWNER_SIGNER_SURI");
    }

    let chain = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;

    let identity_contract = chain
        .get_identity_contract_address()
        .await?
        .context("identity contract address is not set in S3Contracts pallet")?;

    let origin: AccountId32 = owner.into();
    let dest: AccountId32 = identity_contract.into();

    let input_data = encode_identity_grant_delegation(delegate, allowed_operations, expires_at);

    let latest_block = chain
        .inner()
        .at_current_block()
        .await
        .context("failed to access current block for contracts dry-run")?;

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
        .context("contracts dry-run failed for identity::grant_delegation")?;

    println!("dry_run_gas_required={:?}", dry_run.gas_required);

    if !dry_run.debug_message.is_empty() {
        println!(
            "dry_run_debug_message={}",
            String::from_utf8_lossy(&dry_run.debug_message)
        );
    }

    let exec = dry_run
        .result
        .map_err(|err| anyhow!("contracts dry-run dispatch failed: {err:?}"))?;

    println!("dry_run_return_data=0x{}", hex::encode(&exec.data));
    let decoded = decode_exec_result::<(), IdentityError>(&exec.data)
        .context("failed to decode grant_delegation execution result")?;
    println!("dry_run_decoded={decoded:?}");

    decoded
        .map_err(|err| anyhow!("ink dispatch error for identity::grant_delegation: {err:?}"))?
        .map_err(|err| anyhow!("identity contract error for grant_delegation: {err:?}"))?;

    let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url).await?;
    let call = api::tx().contracts().call(
        MultiAddress::Id(dest),
        0u128,
        dry_run.gas_required,
        None,
        input_data,
    );

    let mut tx_api = client.tx().await?;
    let events = tx_api
        .sign_and_submit_then_watch_default(&call, &signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    println!("granted delegation successfully");
    println!("owner=0x{}", hex::encode(owner));
    println!("delegate=0x{}", hex::encode(delegate));
    println!("allowed_operations={allowed_operations}");
    println!("expires_at={expires_at}");
    println!("extrinsic_hash={}", events.extrinsic_hash());

    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("missing required env: {name}"))
}

fn decode_32_hex(value: &str, name: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|e| anyhow!("{name} invalid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to exactly 32 bytes"))?;
    Ok(arr)
}

fn load_owner_signer() -> Result<Keypair> {
    let signer_suri = env::var("S3GW_DELEGATION_OWNER_SIGNER_SURI")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("missing required environment variable: S3GW_DELEGATION_OWNER_SIGNER_SURI")
        })?;

    let uri = SecretUri::from_str(&signer_suri)
        .map_err(|err| anyhow!("S3GW_DELEGATION_OWNER_SIGNER_SURI is invalid: {err:?}"))?;

    Keypair::from_uri(&uri)
        .map_err(|err| anyhow!("failed to load S3GW_DELEGATION_OWNER_SIGNER_SURI: {err:?}"))
}
