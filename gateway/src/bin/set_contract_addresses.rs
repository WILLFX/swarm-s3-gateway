use anyhow::{anyhow, Context, Result};
use std::env;
use subxt::{
    dynamic::{tx, Value},
    OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::{dev, Keypair};

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url = env::var("RPC_URL")
        .or_else(|_| env::var("S3GW_CHAIN_RPC_URL"))
        .map_err(|_| anyhow!("missing RPC_URL or S3GW_CHAIN_RPC_URL"))?;

    let identity_address = env::var("IDENTITY_CONTRACT_ADDRESS_HEX")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| decode_32_hex(&v, "IDENTITY_CONTRACT_ADDRESS_HEX"))
        .transpose()?;

    let bucket_address = env::var("BUCKET_CONTRACT_ADDRESS_HEX")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| decode_32_hex(&v, "BUCKET_CONTRACT_ADDRESS_HEX"))
        .transpose()?;

    if identity_address.is_none() && bucket_address.is_none() {
        return Err(anyhow!(
            "set at least one of IDENTITY_CONTRACT_ADDRESS_HEX or BUCKET_CONTRACT_ADDRESS_HEX"
        ));
    }

    let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;

    let signer = dev::alice();

    if let Some(address) = identity_address {
        submit_sudo_setter(
            &client,
            &signer,
            "set_identity_contract_address",
            &address,
            "identity",
        )
        .await?;
    }

    if let Some(address) = bucket_address {
        submit_sudo_setter(
            &client,
            &signer,
            "set_bucket_contract_address",
            &address,
            "bucket",
        )
        .await?;
    }

    Ok(())
}

async fn submit_sudo_setter(
    client: &OnlineClient<PolkadotConfig>,
    signer: &Keypair,
    setter_name: &'static str,
    address: &[u8; 32],
    label: &'static str,
) -> Result<()> {
    let inner_runtime_call = Value::unnamed_variant(
        "S3Contracts",
        [Value::unnamed_variant(
            setter_name,
            [Value::from_bytes(address.as_slice())],
        )],
    );

    let sudo_call = tx("Sudo", "sudo", vec![inner_runtime_call]);

    let mut tx_api = client.tx().await.context("failed to build tx API")?;
    let events = tx_api
        .sign_and_submit_then_watch_default(&sudo_call, signer)
        .await
        .with_context(|| format!("failed to submit sudo wrapper for {setter_name}"))?
        .wait_for_finalized_success()
        .await
        .with_context(|| format!("{setter_name} failed before finalization"))?;

    println!("set {label} contract address successfully");
    println!("{label}_contract_address=0x{}", hex::encode(address));
    println!("extrinsic_hash={}", events.extrinsic_hash());

    Ok(())
}

fn decode_32_hex(value: &str, name: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).with_context(|| format!("{name} invalid hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to exactly 32 bytes"))?;
    Ok(arr)
}
