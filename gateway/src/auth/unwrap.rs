use crate::traits::SecretUnwrapper;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Source of the gateway master service key.
/// Must come from environment or HSM reference, never hardcoded.
#[derive(Clone, Debug)]
pub enum MasterKeySource {
    EnvKey(Zeroizing<[u8; 32]>),
    HsmRef(String),
}

impl MasterKeySource {
    pub fn load_from_env() -> Result<Self> {
        if let Ok(hex_key) = std::env::var("S3GW_MASTER_SERVICE_KEY_HEX") {
            let bytes = hex::decode(hex_key.trim())
                .context("invalid hex in S3GW_MASTER_SERVICE_KEY_HEX")?;
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "S3GW_MASTER_SERVICE_KEY_HEX must decode to exactly 32 bytes"
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(Self::EnvKey(Zeroizing::new(arr)));
        }

        if let Ok(hsm_ref) = std::env::var("S3GW_HSM_KEY_REF") {
            if hsm_ref.trim().is_empty() {
                return Err(anyhow!("S3GW_HSM_KEY_REF is empty"));
            }
            return Ok(Self::HsmRef(hsm_ref));
        }

        Err(anyhow!(
            "missing key source: set S3GW_MASTER_SERVICE_KEY_HEX or S3GW_HSM_KEY_REF"
        ))
    }
}

#[async_trait]
pub trait HsmClient: Send + Sync {
    async fn decrypt(
        &self,
        key_ref: &str,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
}

pub struct EnvKeyUnwrapper {
    key: Zeroizing<[u8; 32]>,
}

impl EnvKeyUnwrapper {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }
}

#[async_trait]
impl SecretUnwrapper for EnvKeyUnwrapper {
    async fn unwrap_sigv4_secret(
        &self,
        _key_version: u32,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(anyhow!("AES-256-GCM nonce must be 12 bytes"));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key[..])
            .context("failed to initialize AES-256-GCM")?;

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .context("failed to decrypt SigV4 secret blob")?;

        Ok(plaintext)
    }
}

pub struct HsmKeyRefUnwrapper {
    key_ref: String,
    hsm: Arc<dyn HsmClient>,
}

impl HsmKeyRefUnwrapper {
    pub fn new(key_ref: String, hsm: Arc<dyn HsmClient>) -> Self {
        Self { key_ref, hsm }
    }
}

#[async_trait]
impl SecretUnwrapper for HsmKeyRefUnwrapper {
    async fn unwrap_sigv4_secret(
        &self,
        _key_version: u32,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.hsm.decrypt(&self.key_ref, ciphertext, nonce, aad).await
    }
}

/// Build the runtime secret unwrapper from ENV/HSM configuration.
/// This is intentionally runtime-loaded and non-persistent.
pub fn build_secret_unwrapper(
    hsm_client: Option<Arc<dyn HsmClient>>,
) -> Result<Arc<dyn SecretUnwrapper>> {
    match MasterKeySource::load_from_env()? {
        MasterKeySource::EnvKey(key) => Ok(Arc::new(EnvKeyUnwrapper::new(key))),
        MasterKeySource::HsmRef(key_ref) => {
            let hsm = hsm_client.ok_or_else(|| {
                anyhow!("S3GW_HSM_KEY_REF is set but no HsmClient implementation was supplied")
            })?;
            Ok(Arc::new(HsmKeyRefUnwrapper::new(key_ref, hsm)))
        }
    }
}
