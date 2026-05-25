use serde::{Deserialize, Serialize};

pub type Hex32 = String;
pub type SubstrateAccountId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustlessBucketType {
    TrustlessPrivate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientEncryptionKey {
    pub account: SubstrateAccountId,
    pub public_key: String,
    pub key_type: String,
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientEnvelopeContext {
    pub bucket_id: Hex32,
    pub object_key_id: Hex32,
    pub policy_version: u32,
    pub recipients: Vec<RecipientEncryptionKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustlessPutPlan {
    pub bucket: String,
    pub key: String,
    pub bucket_type: TrustlessBucketType,
    pub ciphertext_only: bool,
    pub envelope_context: RecipientEnvelopeContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustlessGetPlan {
    pub bucket: String,
    pub key: String,
    pub bucket_type: TrustlessBucketType,
    pub decrypt_locally: bool,
}
