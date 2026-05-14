use crate::auth::sigv4::RegistryBackedSigV4Validator;
use crate::auth::unwrap::EnvKeyUnwrapper;
use crate::bee::client::BeeClient;
use crate::chain::{anchor_client::ContractAnchorClient, registry::ChainRegistryClient};
use crate::traits::{AnchorClient, RegistryClient, SecretUnwrapper};
use anyhow::{Context, Result, bail};
use common::types::SubstrateAddress32;
use std::{env, fmt, sync::Arc};
use tracing::{info, warn};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub swarm_reference: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
    pub is_private: bool,
    pub encryption_version: Option<u32>,
}

#[derive(Clone)]
pub struct AppState {
    pub sigv4_validator: Arc<RegistryBackedSigV4Validator>,
    pub registry_client: Arc<dyn RegistryClient>,
    pub secret_unwrapper: Arc<dyn SecretUnwrapper>,
    pub bee_client: Arc<BeeClient>,
    pub anchor_client: Arc<dyn AnchorClient>,
    pub master_service_key: [u8; 32],
    pub identity_contract_address: Option<SubstrateAddress32>,
    pub bucket_contract_address: Option<SubstrateAddress32>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("sigv4_validator", &"Arc<RegistryBackedSigV4Validator>")
            .field("registry_client", &"Arc<dyn RegistryClient>")
            .field("secret_unwrapper", &"Arc<dyn SecretUnwrapper>")
            .field("bee_client", &"Arc<BeeClient>")
            .field("anchor_client", &"Arc<dyn AnchorClient>")
            .field("master_service_key", &"<redacted>")
            .field(
                "identity_contract_address",
                &self.identity_contract_address.as_ref().map(hex::encode),
            )
            .field(
                "bucket_contract_address",
                &self.bucket_contract_address.as_ref().map(hex::encode),
            )
            .finish()
    }
}

pub async fn build_production_state() -> Result<AppState> {
    let master_service_key = load_master_service_key()?;

    let expected_service = env::var("S3GW_EXPECTED_SERVICE").unwrap_or_else(|_| "s3".to_string());

    let expected_region = env::var("S3GW_EXPECTED_REGION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let allow_unsigned_payload = read_bool_env("S3GW_ALLOW_UNSIGNED_PAYLOAD")?.unwrap_or(false);

    let bee_api_url = required_env("S3GW_BEE_API_URL")?;

    let bee_client = Arc::new(
        BeeClient::from_env(&bee_api_url)
            .with_context(|| format!("failed to build Bee client for {bee_api_url}"))?,
    );

    let chain_registry_client = build_chain_registry_client().await?;
    let identity_contract_address = chain_registry_client
        .get_identity_contract_address()
        .await
        .context("failed to read IdentityContractAddress from S3Contracts pallet")?;
    let bucket_contract_address = chain_registry_client
        .get_bucket_contract_address()
        .await
        .context("failed to read BucketContractAddress from S3Contracts pallet")?
        .context("bucket contract address is not set in S3Contracts pallet")?;

    match identity_contract_address {
        Some(address) => info!(
            identity_contract_address = %hex::encode(address),
            "loaded identity contract address from S3Contracts pallet"
        ),
        None => warn!("identity contract address is not set in S3Contracts pallet"),
    }

    info!(
        bucket_contract_address = %hex::encode(bucket_contract_address),
        "loaded required bucket contract address from S3Contracts pallet"
    );

    let registry_client: Arc<dyn RegistryClient> = chain_registry_client.clone();

    let secret_unwrapper: Arc<dyn SecretUnwrapper> =
        Arc::new(EnvKeyUnwrapper::new(Zeroizing::new(master_service_key)));

    let sigv4_validator = Arc::new(RegistryBackedSigV4Validator {
        registry: registry_client.clone(),
        unwrapper: secret_unwrapper.clone(),
        expected_service,
        expected_region,
        allow_unsigned_payload,
    });

    let anchor_caller = load_anchor_caller_address()?;
    let anchor_client: Arc<dyn AnchorClient> = Arc::new(ContractAnchorClient::new(
        chain_registry_client.inner().clone(),
        bucket_contract_address,
        subxt_signer::sr25519::dev::alice(),
        anchor_caller,
    ));

    Ok(AppState {
        sigv4_validator,
        registry_client,
        secret_unwrapper,
        bee_client,
        anchor_client,
        master_service_key,
        identity_contract_address,
        bucket_contract_address: Some(bucket_contract_address),
    })
}

fn load_anchor_caller_address() -> Result<SubstrateAddress32> {
    const DEV_ALICE_ACCOUNT: SubstrateAddress32 = [
        0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f,
        0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d,
        0xa2, 0x7d,
    ];

    let Some(value) = env::var("S3GW_ANCHOR_CALLER_HEX")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        return Ok(DEV_ALICE_ACCOUNT);
    };

    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed)
        .with_context(|| "S3GW_ANCHOR_CALLER_HEX must be a 32-byte hex account id")?;

    let address: SubstrateAddress32 = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("S3GW_ANCHOR_CALLER_HEX must decode to exactly 32 bytes"))?;

    Ok(address)
}

async fn build_chain_registry_client() -> Result<Arc<ChainRegistryClient>> {
    let rpc_url = required_env("S3GW_CHAIN_RPC_URL")?;
    let client = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to build chain registry client for {rpc_url}"))?;
    Ok(Arc::new(client))
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required environment variable: {name}"))
}

fn read_bool_env(name: &str) -> Result<Option<bool>> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            other => bail!("invalid boolean value for {name}: {other}"),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("environment variable {name} is not valid UTF-8")
        }
    }
}

fn load_master_service_key() -> Result<[u8; 32]> {
    let raw = required_env("S3GW_MASTER_SERVICE_KEY_HEX")?;
    let trimmed = raw.trim().trim_start_matches("0x");

    let bytes =
        hex::decode(trimmed).with_context(|| "S3GW_MASTER_SERVICE_KEY_HEX must be valid hex")?;

    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("S3GW_MASTER_SERVICE_KEY_HEX must decode to exactly 32 bytes")
    })?;

    Ok(key)
}

#[allow(dead_code)]
async fn build_registry_client() -> Result<Arc<dyn RegistryClient>> {
    let rpc_url = required_env("S3GW_CHAIN_RPC_URL")?;
    let client = ChainRegistryClient::connect(&rpc_url)
        .await
        .with_context(|| format!("failed to build chain registry client for {rpc_url}"))?;
    Ok(Arc::new(client))
}
