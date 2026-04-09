// Secret unwrapping implementation will live here.
use crate::traits::SecretUnwrapper;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;

/// Handles in-memory decryption of S3 secrets using the Master Service Key.
pub struct EnvKeyUnwrapper {
    /// Zeroizing ensures the key is wiped from RAM when this struct is dropped.
    master_key: Zeroizing<[u8; 32]>,
}

impl EnvKeyUnwrapper {
    pub fn new(master_key: Zeroizing<[u8; 32]>) -> Self {
        Self { master_key }
    }
}

impl SecretUnwrapper for EnvKeyUnwrapper {
    fn unwrap_secret(&self, encrypted_secret: &[u8]) -> Result<Vec<u8>> {
        // We expect the encrypted_secret to be: [12-byte Nonce] + [Encrypted Data]
        if encrypted_secret.len() < 12 {
            return Err(anyhow!("encrypted secret is too short to contain a nonce"));
        }

        let (nonce_bytes, ciphertext) = encrypted_secret.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let cipher = Aes256Gcm::new_from_slice(&*self.master_key)
            .map_err(|_| anyhow!("invalid master service key length"))?;

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("failed to decrypt S3 secret: {}", e))?;

        Ok(decrypted)
    }
}
