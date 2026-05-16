use anyhow::{Context, Result, anyhow};
use gateway::{chain::registry::ChainRegistryClient, crypto::bucket_name_hash};
use sp_core::{Pair as _, sr25519};
use std::env;

fn decode_32_hex(value: &str, name: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).with_context(|| format!("{name} invalid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to exactly 32 bytes"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let op = env::args().nth(1).ok_or_else(|| {
        anyhow!("usage: sign_bucket_op <create|delete|increment> <bucket> [private|public]")
    })?;

    let bucket = env::args().nth(2).ok_or_else(|| {
        anyhow!("usage: sign_bucket_op <create|delete|increment> <bucket> [private|public]")
    })?;

    let visibility = env::args().nth(3).unwrap_or_else(|| "public".to_string());
    let is_private = visibility.eq_ignore_ascii_case("private");

    let rpc_url = env::var("RPC_URL")
        .or_else(|_| env::var("S3GW_CHAIN_RPC_URL"))
        .map_err(|_| anyhow!("missing RPC_URL or S3GW_CHAIN_RPC_URL"))?;

    let owner = env::var("OWNER_HEX")
        .ok()
        .map(|v| decode_32_hex(&v, "OWNER_HEX"))
        .transpose()?
        .unwrap_or([
            0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9,
            0x9f, 0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7,
            0xa5, 0x6d, 0xa2, 0x7d,
        ]);

    let pair = load_bucket_owner_signer()?;

    if pair.public().0 != owner {
        return Err(anyhow!(
            "OWNER_HEX must match the public key derived from S3GW_BUCKET_OWNER_SIGNER_SURI"
        ));
    }

    let chain = ChainRegistryClient::connect(&rpc_url).await?;
    let bucket_contract = chain
        .get_bucket_contract_address()
        .await?
        .ok_or_else(|| anyhow!("bucket contract address is not set in S3Contracts pallet"))?;

    let nonce = chain.get_owner_nonce(owner).await?;
    let bucket_hash = bucket_name_hash(&owner, &bucket);

    let tag: &[u8] = match op.as_str() {
        "create" => b"s3gw/v1/create_bucket",
        "delete" => b"s3gw/v1/delete_bucket",
        "increment" => b"s3gw/v1/increment_encryption_version",
        other => {
            return Err(anyhow!(
                "unsupported op: {other}; use create, delete, or increment"
            ));
        }
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(tag);
    payload.extend_from_slice(&bucket_contract);
    payload.extend_from_slice(&bucket_hash);

    if op == "create" {
        payload.push(if is_private { 1 } else { 0 });
    }

    payload.extend_from_slice(&nonce.to_le_bytes());

    let signature = pair.sign(&payload);

    println!("op={op}");
    println!("bucket={bucket}");
    println!("is_private={is_private}");
    println!("owner=0x{}", hex::encode(owner));
    println!("bucket_contract=0x{}", hex::encode(bucket_contract));
    println!("bucket_hash=0x{}", hex::encode(bucket_hash));
    println!("owner_nonce={nonce}");
    println!("x-s3gw-owner-signature=0x{}", hex::encode(signature.0));

    Ok(())
}

fn load_bucket_owner_signer() -> Result<sr25519::Pair> {
    let suri = env::var("S3GW_BUCKET_OWNER_SIGNER_SURI")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("missing required environment variable: S3GW_BUCKET_OWNER_SIGNER_SURI")
        })?;

    sr25519::Pair::from_string(&suri, None)
        .map_err(|err| anyhow!("failed to load S3GW_BUCKET_OWNER_SIGNER_SURI: {err:?}"))
}
