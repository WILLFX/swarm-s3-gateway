use crate::traits::SecretUnwrapper;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use zeroize::Zeroizing;

pub struct EnvKeyUnwrapper {
    master_key: Zeroizing<[u8; 32]>,
}

impl EnvKeyUnwrapper {
    pub fn new(master_key: Zeroizing<[u8; 32]>) -> Self {
        Self { master_key }
    }
}

#[async_trait]
impl SecretUnwrapper for EnvKeyUnwrapper {
    async fn unwrap_sigv4_secret(
        &self,
        _key_version: u32,
        nonce_bytes: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&*self.master_key)
            .map_err(|_| anyhow!("Invalid master service key length"))?;

        // S3 secrets use 12-byte nonces for AES-GCM
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let payload = Payload {
            msg: ciphertext,
            aad: aad,
        };

        let decrypted = cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow!("Failed to decrypt S3 secret: {}", e))?;

        Ok(decrypted)
    }
}


