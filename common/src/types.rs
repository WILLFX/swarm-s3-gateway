use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub type AccessKeyHash = [u8; 32];
pub type SubstrateAddress32 = [u8; 32];
pub type BucketId = [u8; 32];
pub type ObjectKeyId = [u8; 32];
pub type Etag = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRegistryEntry {
    pub owner: SubstrateAddress32,
    pub encrypted_sigv4_secret: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsPrincipal {
    pub access_key_id: String,
    pub owner: SubstrateAddress32,
}
