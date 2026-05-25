#![cfg_attr(not(feature = "std"), no_std)]

use ink::prelude::vec::Vec;
#[cfg(feature = "std")]
use ink::storage::traits::StorageLayout;
use scale::{Decode, Encode};
use scale_info::TypeInfo;

pub type AccountId32 = [u8; 32];

pub const OP_PUT_OBJECT: u32 = 0b00000001;
pub const OP_GET_OBJECT: u32 = 0b00000010;
pub const OP_DELETE_OBJECT: u32 = 0b00000100;
pub const OP_LIST_OBJECTS: u32 = 0b00001000;
pub const OP_HEAD_OBJECT: u32 = 0b00010000;
pub const OP_CREATE_BUCKET: u32 = 0b00100000;
pub const OP_DELETE_BUCKET: u32 = 0b01000000;
pub const OP_ALL: u32 = 0b01111111;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(StorageLayout))]
pub struct IdentityRecord {
    pub owner: AccountId32,
    pub encrypted_sigv4_secret: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(StorageLayout))]
pub struct DelegationEntry {
    pub delegate: AccountId32,
    pub allowed_operations: u32,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(StorageLayout))]
pub struct EncryptionKeyRecord {
    pub owner: AccountId32,
    pub public_key: Vec<u8>,
    pub key_type: Vec<u8>,
    pub key_version: u32,
    pub enabled: bool,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(StorageLayout))]
pub struct BucketRecord {
    pub owner: AccountId32,
    pub is_private: bool,
    pub encryption_version: u32,
    pub creation_date: u64,
    pub bucket_manifest_root: Vec<u8>,
}

#[ink::trait_definition]
pub trait S3IdentityRead {
    #[ink(message)]
    fn get_identity(&self, access_key_hash: [u8; 32]) -> Option<IdentityRecord>;

    #[ink(message)]
    fn is_authorized(&self, access_key_hash: [u8; 32], operation: u32) -> bool;

    #[ink(message)]
    fn is_delegate_authorized(
        &self,
        owner: AccountId32,
        delegate: AccountId32,
        operation: u32,
    ) -> bool;

    #[ink(message)]
    fn get_delegation(&self, owner: AccountId32, delegate: AccountId32) -> Option<DelegationEntry>;

    #[ink(message)]
    fn get_encryption_key(&self, owner: AccountId32) -> Option<EncryptionKeyRecord>;
}
