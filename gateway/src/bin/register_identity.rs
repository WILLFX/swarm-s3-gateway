use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, anyhow, bail};
use gateway::{
    chain::registry::ChainRegistryClient,
    contracts_abi::{IdentityError, decode_exec_result, encode_identity_register_identity},
    s3_runtime::api,
};
use sha2::{Digest, Sha256};
use std::{
    env,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32, MultiAddress},
};
use subxt_signer::{SecretUri, sr25519::Keypair};

const ALICE_OWNER_HEX: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url = required_env("RPC_URL")?;
    let master_key_hex = required_env("MASTER_SERVICE_KEY_HEX")?;
    let access_key_id = required_env("AWS_ACCESS_KEY_ID")?;
    let secret_access_key = required_env("AWS_SECRET_ACCESS_KEY")?;
    let owner_hex = env::var("OWNER_HEX").unwrap_or_else(|_| ALICE_OWNER_HEX.to_string());

    let master_key = decode_32_hex(&master_key_hex, "MASTER_SERVICE_KEY_HEX")?;
    let owner = decode_32_hex(&owner_hex, "OWNER_HEX")?;
    let signer = load_identity_registrar_signer()?;
    let signer_account = signer.public_key().0;

    if signer_account != owner {
        bail!(
            "OWNER_HEX must match the public key derived from S3GW_IDENTITY_REGISTRAR_SIGNER_SURI"
        );
    }

    let access_key_hash = sha256_32(access_key_id.as_bytes());

    let nonce = derive_nonce(&access_key_id, &secret_access_key);
    let encrypted_sigv4_secret = encrypt_secret(
        &master_key,
        &nonce,
        &access_key_hash,
        secret_access_key.as_bytes(),
    )?;

    let chain = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;

    let identity_contract = chain
        .get_identity_contract_address()
        .await?
        .context("identity contract address is not set in S3Contracts pallet")?;

    let origin: AccountId32 = owner.into();
    let dest: AccountId32 = identity_contract.into();

    let input_data =
        encode_identity_register_identity(access_key_hash, encrypted_sigv4_secret.clone(), nonce);

    let latest_block = chain
        .inner()
        .at_current_block()
        .await
        .context("failed to access current block for contracts dry-run")?;

    let dry_run = latest_block
        .runtime_apis()
        .call(api::runtime_apis().contracts_api().call(
            origin.clone(),
            dest.clone(),
            0u128,
            None,
            None,
            input_data.clone(),
        ))
        .await
        .context("contracts dry-run failed")?;

    println!("dry_run_gas_required={:?}", dry_run.gas_required);

    if !dry_run.debug_message.is_empty() {
        println!(
            "dry_run_debug_message={}",
            String::from_utf8_lossy(&dry_run.debug_message)
        );
    }

    match &dry_run.result {
        Ok(exec) => {
            println!("dry_run_return_data=0x{}", hex::encode(&exec.data));
            match decode_exec_result::<(), IdentityError>(&exec.data) {
                Ok(decoded) => println!("dry_run_decoded={decoded:?}"),
                Err(err) => println!("dry_run_decode_error={err}"),
            }
        }
        Err(dispatch_error) => {
            bail!("dry run returned dispatch error: {dispatch_error:?}");
        }
    }

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

    println!("registered identity successfully");
    println!("access_key_id={access_key_id}");
    println!("access_key_hash=0x{}", hex::encode(access_key_hash));
    println!("owner=0x{}", hex::encode(owner));
    println!("nonce=0x{}", hex::encode(nonce));
    println!("ciphertext_len={}", encrypted_sigv4_secret.len());
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

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn derive_nonce(access_key_id: &str, secret: &str) -> [u8; 12] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string();
    let digest = Sha256::digest(format!("{access_key_id}:{secret}:{now}").as_bytes());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

fn encrypt_secret(
    master_key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| anyhow!("failed to initialize AES-256-GCM"))?;

    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(GenericArray::from_slice(nonce), aad.as_slice(), &mut buf)
        .map_err(|_| anyhow!("failed to encrypt secret"))?;

    Ok(buf)
}

fn load_identity_registrar_signer() -> Result<Keypair> {
    let signer_suri = env::var("S3GW_IDENTITY_REGISTRAR_SIGNER_SURI")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("missing required environment variable: S3GW_IDENTITY_REGISTRAR_SIGNER_SURI")
        })?;

    let uri = SecretUri::from_str(&signer_suri)
        .map_err(|err| anyhow!("S3GW_IDENTITY_REGISTRAR_SIGNER_SURI is invalid: {err:?}"))?;

    Keypair::from_uri(&uri)
        .map_err(|err| anyhow!("failed to load S3GW_IDENTITY_REGISTRAR_SIGNER_SURI: {err:?}"))
}
