use crate::auth::sigv4::RegistryBackedSigV4Validator;
use crate::auth::unwrap::EnvKeyUnwrapper;
use crate::bee::client::BeeClient;
use crate::traits::{AnchorClient, RegistryClient, SecretUnwrapper};
use anyhow::{bail, Context, Result};
use std::{env, fmt, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AppState {
    pub sigv4_validator: Arc<RegistryBackedSigV4Validator>,
    pub registry_client: Arc<dyn RegistryClient>,
    pub secret_unwrapper: Arc<dyn SecretUnwrapper>,
    pub bee_client: Arc<BeeClient>,
    pub anchor_client: Option<Arc<dyn AnchorClient>>,
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("sigv4_validator", &"Arc<RegistryBackedSigV4Validator>")
            .field("registry_client", &"Arc<dyn RegistryClient>")
            .field("secret_unwrapper", &"Arc<dyn SecretUnwrapper>")
            .field("bee_client", &"Arc<BeeClient>")
            .field(
                "anchor_client",
                if self.anchor_client.is_some() {
                    &"Some(Arc<dyn AnchorClient>)"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

pub async fn build_production_state() -> Result<AppState> {
    let master_service_key = load_master_service_key()?;

    let expected_service =
        env::var("S3GW_EXPECTED_SERVICE").unwrap_or_else(|_| "s3".to_string());

    let expected_region = env::var("S3GW_EXPECTED_REGION")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let allow_unsigned_payload =
        read_bool_env("S3GW_ALLOW_UNSIGNED_PAYLOAD")?.unwrap_or(false);

    let bee_api_url = required_env("S3GW_BEE_API_URL")?;

    // BeeClient::from_env() will also load and validate:
    // - S3GW_BEE_STAMP_BATCH_ID
    // - S3GW_GAS_TANK_SEED
    let bee_client = Arc::new(
        BeeClient::from_env(&bee_api_url)
            .with_context(|| format!("failed to build Bee client for {bee_api_url}"))?,
    );

    let registry_client = build_registry_client().await?;

    let secret_unwrapper: Arc<dyn SecretUnwrapper> =
        Arc::new(EnvKeyUnwrapper::new(Zeroizing::new(master_service_key)));

    let sigv4_validator = Arc::new(RegistryBackedSigV4Validator {
        registry: registry_client.clone(),
        unwrapper: secret_unwrapper.clone(),
        expected_service,
        expected_region,
        allow_unsigned_payload,
    });

    Ok(AppState {
        sigv4_validator,
        registry_client,
        secret_unwrapper,
        bee_client,
        anchor_client: None,
    })
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

    let bytes = hex::decode(trimmed)
        .with_context(|| "S3GW_MASTER_SERVICE_KEY_HEX must be valid hex")?;

    let key: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("S3GW_MASTER_SERVICE_KEY_HEX must decode to exactly 32 bytes")
    })?;

    Ok(key)
}

async fn build_registry_client() -> Result<Arc<dyn RegistryClient>> {
    todo!("replace with your concrete registry client constructor")
}
