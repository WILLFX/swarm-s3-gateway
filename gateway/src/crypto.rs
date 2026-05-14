use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
};
use anyhow::{Context, Result, anyhow, bail};
use blake2::{
    Blake2b,
    digest::{Digest, consts::U32},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use common::types::SubstrateAddress32;

type HmacSha256 = Hmac<Sha256>;
type Blake2b256 = Blake2b<U32>;

pub fn bucket_name_hash(owner: &SubstrateAddress32, bucket_name: &str) -> [u8; 32] {
    let normalized = bucket_name.to_ascii_lowercase();
    let mut hasher = Blake2b256::new();
    hasher.update(owner);
    hasher.update(normalized.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

pub fn object_key_hash(object_key: &str) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(object_key.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

pub fn derive_object_encryption_key(
    master_key: &[u8; 32],
    bucket_name: &str,
    object_key: &str,
    encryption_version: u32,
) -> [u8; 32] {
    derive_hmac_32(
        master_key,
        format!("{bucket_name}/{object_key}/{encryption_version}").as_bytes(),
    )
}

pub fn derive_object_encryption_nonce(
    master_key: &[u8; 32],
    bucket_name: &str,
    object_key: &str,
    encryption_version: u32,
) -> [u8; 12] {
    let digest = derive_hmac_32(
        master_key,
        format!("nonce/{bucket_name}/{object_key}/{encryption_version}").as_bytes(),
    );

    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

pub fn derive_manifest_encryption_key(
    master_key: &[u8; 32],
    bucket_name: &str,
    object_key: &str,
    encryption_version: u32,
) -> [u8; 32] {
    derive_hmac_32(
        master_key,
        format!("manifest/{bucket_name}/{object_key}/{encryption_version}").as_bytes(),
    )
}

pub fn derive_manifest_encryption_nonce(
    master_key: &[u8; 32],
    bucket_name: &str,
    object_key: &str,
    encryption_version: u32,
) -> [u8; 12] {
    let digest = derive_hmac_32(
        master_key,
        format!("nonce/manifest/{bucket_name}/{object_key}/{encryption_version}").as_bytes(),
    );

    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

pub const AES_GCM_NONCE_LEN: usize = 12;

pub fn encrypt_blob_random(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    getrandom::getrandom(&mut nonce).context("failed to generate AES-GCM nonce")?;

    let ciphertext = encrypt_bytes(key, &nonce, aad, plaintext)?;

    let mut blob = Vec::with_capacity(AES_GCM_NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}

pub fn decrypt_blob(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < AES_GCM_NONCE_LEN {
        bail!(
            "encrypted blob too short: expected at least {} bytes, got {}",
            AES_GCM_NONCE_LEN,
            blob.len()
        );
    }

    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    nonce.copy_from_slice(&blob[..AES_GCM_NONCE_LEN]);

    decrypt_bytes(key, &nonce, aad, &blob[AES_GCM_NONCE_LEN..])
}

pub fn derive_owner_catalog_encryption_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
) -> [u8; 32] {
    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/owner-catalog-key");
    message.push(0);
    message.extend_from_slice(owner);

    derive_hmac_32(master_key, &message)
}

pub fn derive_private_bucket_manifest_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket_name: &str,
    encryption_version: u32,
) -> [u8; 32] {
    let normalized_bucket = bucket_name.to_ascii_lowercase();

    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/private-bucket-manifest-key");
    message.push(0);
    message.extend_from_slice(owner);
    message.push(0);
    message.extend_from_slice(normalized_bucket.as_bytes());
    message.push(0);
    message.extend_from_slice(&encryption_version.to_le_bytes());

    derive_hmac_32(master_key, &message)
}

pub fn derive_private_object_index_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket_name: &str,
    encryption_version: u32,
) -> [u8; 32] {
    let normalized_bucket = bucket_name.to_ascii_lowercase();

    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/private-object-index-key");
    message.push(0);
    message.extend_from_slice(owner);
    message.push(0);
    message.extend_from_slice(normalized_bucket.as_bytes());
    message.push(0);
    message.extend_from_slice(&encryption_version.to_le_bytes());

    derive_hmac_32(master_key, &message)
}

pub fn private_object_key_id(private_index_key: &[u8; 32], object_key: &str) -> [u8; 32] {
    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/private-object-key-id");
    message.push(0);
    message.extend_from_slice(object_key.as_bytes());

    derive_hmac_32(private_index_key, &message)
}

pub fn derive_private_object_payload_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket_name: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
) -> [u8; 32] {
    let normalized_bucket = bucket_name.to_ascii_lowercase();

    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/private-object-payload-key");
    message.push(0);
    message.extend_from_slice(owner);
    message.push(0);
    message.extend_from_slice(normalized_bucket.as_bytes());
    message.push(0);
    message.extend_from_slice(object_key_id);
    message.push(0);
    message.extend_from_slice(&encryption_version.to_le_bytes());

    derive_hmac_32(master_key, &message)
}

pub fn derive_private_object_manifest_key(
    master_key: &[u8; 32],
    owner: &SubstrateAddress32,
    bucket_name: &str,
    object_key_id: &[u8; 32],
    encryption_version: u32,
) -> [u8; 32] {
    let normalized_bucket = bucket_name.to_ascii_lowercase();

    let mut message = Vec::new();
    message.extend_from_slice(b"s3gw/v1/private-object-manifest-key");
    message.push(0);
    message.extend_from_slice(owner);
    message.push(0);
    message.extend_from_slice(normalized_bucket.as_bytes());
    message.push(0);
    message.extend_from_slice(object_key_id);
    message.push(0);
    message.extend_from_slice(&encryption_version.to_le_bytes());

    derive_hmac_32(master_key, &message)
}

pub fn encrypt_bytes(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("failed to initialize AES-256-GCM"))?;

    let mut buf = plaintext.to_vec();
    cipher
        .encrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buf)
        .map_err(|_| anyhow!("failed to encrypt payload"))?;

    Ok(buf)
}

pub fn decrypt_bytes(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("failed to initialize AES-256-GCM"))?;

    let mut buf = ciphertext.to_vec();
    cipher
        .decrypt_in_place(GenericArray::from_slice(nonce), aad, &mut buf)
        .map_err(|_| anyhow!("failed to decrypt payload"))?;

    Ok(buf)
}

fn derive_hmac_32(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let output = mac.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&output);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_hash_is_owner_scoped_and_lowercase_normalized() {
        let owner_a = [1u8; 32];
        let owner_b = [2u8; 32];

        let h1 = bucket_name_hash(&owner_a, "Photos");
        let h2 = bucket_name_hash(&owner_a, "photos");
        let h3 = bucket_name_hash(&owner_b, "photos");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn object_key_derivations_are_deterministic() {
        let master = [7u8; 32];

        let k1 = derive_object_encryption_key(&master, "bucket", "a/b.txt", 1);
        let k2 = derive_object_encryption_key(&master, "bucket", "a/b.txt", 1);
        let n1 = derive_object_encryption_nonce(&master, "bucket", "a/b.txt", 1);
        let n2 = derive_object_encryption_nonce(&master, "bucket", "a/b.txt", 1);

        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
    }

    #[test]
    fn encrypt_roundtrip_works() {
        let master = [9u8; 32];
        let key = derive_object_encryption_key(&master, "bucket", "file.txt", 3);
        let nonce = derive_object_encryption_nonce(&master, "bucket", "file.txt", 3);

        let plaintext = b"hello private bucket";
        let aad = b"bucket/file.txt";

        let ciphertext = encrypt_bytes(&key, &nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt_bytes(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_blob_random_uses_distinct_nonces() {
        let key = [3u8; 32];
        let aad = b"private/blob";
        let plaintext = b"same plaintext";

        let first = encrypt_blob_random(&key, aad, plaintext).unwrap();
        let second = encrypt_blob_random(&key, aad, plaintext).unwrap();

        assert_ne!(first, second);
        assert_eq!(&first[..AES_GCM_NONCE_LEN].len(), &AES_GCM_NONCE_LEN);
        assert_eq!(&second[..AES_GCM_NONCE_LEN].len(), &AES_GCM_NONCE_LEN);
    }

    #[test]
    fn encrypt_blob_random_roundtrip_works() {
        let key = [4u8; 32];
        let aad = b"private/blob/aad";
        let plaintext = b"private payload";

        let blob = encrypt_blob_random(&key, aad, plaintext).unwrap();
        let decrypted = decrypt_blob(&key, aad, &blob).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_blob_with_wrong_aad_fails() {
        let key = [5u8; 32];
        let blob = encrypt_blob_random(&key, b"right-aad", b"secret").unwrap();

        let err = decrypt_blob(&key, b"wrong-aad", &blob).unwrap_err();

        assert!(err.to_string().contains("failed to decrypt payload"));
    }

    #[test]
    fn private_object_key_id_is_keyed_and_deterministic() {
        let master = [6u8; 32];
        let owner = [7u8; 32];

        let index_key_a = derive_private_object_index_key(&master, &owner, "Photos", 1);
        let index_key_b = derive_private_object_index_key(&master, &owner, "photos", 1);
        let index_key_c = derive_private_object_index_key(&master, &owner, "photos", 2);

        assert_eq!(index_key_a, index_key_b);
        assert_ne!(index_key_a, index_key_c);

        let id1 = private_object_key_id(&index_key_a, "cats/001.jpg");
        let id2 = private_object_key_id(&index_key_a, "cats/001.jpg");
        let id3 = private_object_key_id(&index_key_c, "cats/001.jpg");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn private_payload_and_manifest_keys_are_domain_separated() {
        let master = [8u8; 32];
        let owner = [9u8; 32];
        let index_key = derive_private_object_index_key(&master, &owner, "bucket", 1);
        let object_id = private_object_key_id(&index_key, "file.txt");

        let payload_key =
            derive_private_object_payload_key(&master, &owner, "bucket", &object_id, 1);
        let manifest_key =
            derive_private_object_manifest_key(&master, &owner, "bucket", &object_id, 1);
        let bucket_manifest_key = derive_private_bucket_manifest_key(&master, &owner, "bucket", 1);
        let owner_catalog_key = derive_owner_catalog_encryption_key(&master, &owner);

        assert_ne!(payload_key, manifest_key);
        assert_ne!(payload_key, bucket_manifest_key);
        assert_ne!(manifest_key, bucket_manifest_key);
        assert_ne!(owner_catalog_key, bucket_manifest_key);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let master = [9u8; 32];
        let wrong_master = [8u8; 32];

        let key = derive_object_encryption_key(&master, "bucket", "file.txt", 3);
        let nonce = derive_object_encryption_nonce(&master, "bucket", "file.txt", 3);

        let wrong_key = derive_object_encryption_key(&wrong_master, "bucket", "file.txt", 3);

        let ciphertext = encrypt_bytes(&key, &nonce, b"", b"secret").unwrap();
        let err = decrypt_bytes(&wrong_key, &nonce, b"", &ciphertext).unwrap_err();

        assert!(err.to_string().contains("failed to decrypt payload"));
    }
}
