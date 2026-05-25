use anyhow::{Context, Result, anyhow, bail};
use gateway::{
    chain::registry::ChainRegistryClient,
    contracts_abi::{
        IdentityError, decode_exec_result, encode_identity_disable_encryption_key,
        encode_identity_register_encryption_key, encode_identity_rotate_encryption_key,
    },
    s3_runtime::api,
};
use std::{env, str::FromStr};
use subxt::{
    OnlineClient, PolkadotConfig,
    utils::{AccountId32, MultiAddress},
};
use subxt_signer::{SecretUri, sr25519::Keypair};

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url = required_env("RPC_URL")?;
    let signer = load_identity_key_signer()?;

    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(|| usage_error())?;

    let input_data = match command.as_str() {
        "register" => {
            let public_key = decode_hex_arg(args.next(), "public_key_hex")?;
            let key_type = parse_key_type_arg(args.next())?;
            ensure_no_extra_args(args)?;
            encode_identity_register_encryption_key(public_key, key_type)
        }
        "rotate" => {
            let public_key = decode_hex_arg(args.next(), "public_key_hex")?;
            let key_type = parse_key_type_arg(args.next())?;
            ensure_no_extra_args(args)?;
            encode_identity_rotate_encryption_key(public_key, key_type)
        }
        "disable" => {
            ensure_no_extra_args(args)?;
            encode_identity_disable_encryption_key()
        }
        _ => return Err(usage_error()),
    };

    let chain = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to connect to chain RPC at {rpc_url}"))?;

    let identity_contract = chain
        .get_identity_contract_address()
        .await?
        .context("identity contract address is not set in S3Contracts pallet")?;

    let origin: AccountId32 = signer.public_key().0.into();
    let dest: AccountId32 = identity_contract.into();

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

    println!("identity encryption key command completed successfully");
    println!("command={command}");
    println!("owner=0x{}", hex::encode(signer.public_key().0));
    println!("extrinsic_hash={}", events.extrinsic_hash());

    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("missing required env: {name}"))
}

fn load_identity_key_signer() -> Result<Keypair> {
    let signer_suri = env::var("S3GW_IDENTITY_KEY_SIGNER_SURI")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            anyhow!("missing required environment variable: S3GW_IDENTITY_KEY_SIGNER_SURI")
        })?;

    let uri = SecretUri::from_str(&signer_suri)
        .map_err(|err| anyhow!("S3GW_IDENTITY_KEY_SIGNER_SURI is invalid: {err:?}"))?;

    Keypair::from_uri(&uri)
        .map_err(|err| anyhow!("failed to load S3GW_IDENTITY_KEY_SIGNER_SURI: {err:?}"))
}

fn decode_hex_arg(value: Option<String>, name: &str) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| usage_error())?;
    let trimmed = value.trim().trim_start_matches("0x");

    if trimmed.is_empty() {
        bail!("{name} must not be empty");
    }

    hex::decode(trimmed).map_err(|err| anyhow!("{name} invalid hex: {err}"))
}

fn parse_key_type_arg(value: Option<String>) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| usage_error())?;
    let trimmed = value.trim();

    if trimmed.is_empty() {
        bail!("key_type must not be empty");
    }

    Ok(trimmed.as_bytes().to_vec())
}

fn ensure_no_extra_args(mut args: impl Iterator<Item = String>) -> Result<()> {
    if let Some(extra) = args.next() {
        bail!("unexpected extra argument: {extra}");
    }

    Ok(())
}

fn usage_error() -> anyhow::Error {
    anyhow!(
        "usage: identity_encryption_key register <public_key_hex> <key_type> | rotate <public_key_hex> <key_type> | disable"
    )
}
