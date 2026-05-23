use parity_scale_codec::{Decode, Encode};

pub type AccountId32 = [u8; 32];
pub type AccessKeyHash = [u8; 32];
pub type BucketNameHash = [u8; 32];
pub type ContractHash = [u8; 32];
pub type SecretNonce = [u8; 12];

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct IdentityRecord {
    pub owner: AccountId32,
    pub encrypted_sigv4_secret: Vec<u8>,
    pub nonce: SecretNonce,
    pub key_version: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DelegationEntry {
    pub delegate: AccountId32,
    pub allowed_operations: u32,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BucketRecord {
    pub owner: AccountId32,
    pub is_private: bool,
    pub encryption_version: u32,
    pub creation_date: u64,
    pub bucket_manifest_root: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum InkLangError {
    #[codec(index = 1)]
    CouldNotReadInput,
}

pub type QueryResult<T> = Result<T, InkLangError>;
pub type ExecResult<T, E> = Result<Result<T, E>, InkLangError>;

/// Gateway-side labels only.
/// The SCALE discriminants are what matter for decoding.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum IdentityError {
    #[codec(index = 0)]
    Error0,
    #[codec(index = 1)]
    Error1,
    #[codec(index = 2)]
    Error2,
    #[codec(index = 3)]
    Error3,
    #[codec(index = 4)]
    Error4,
    #[codec(index = 5)]
    Error5,
    #[codec(index = 6)]
    Error6,
    #[codec(index = 7)]
    Error7,
}

/// Gateway-side labels only.
/// The SCALE discriminants are what matter for decoding.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum BucketError {
    #[codec(index = 0)]
    Error0,
    #[codec(index = 1)]
    Error1,
    #[codec(index = 2)]
    Error2,
    #[codec(index = 3)]
    Error3,
    #[codec(index = 4)]
    Error4,
    #[codec(index = 5)]
    Error5,
    #[codec(index = 6)]
    Error6,
    #[codec(index = 7)]
    Error7,
    #[codec(index = 8)]
    Error8,
}

pub const IDENTITY_REGISTER_IDENTITY_SELECTOR: [u8; 4] = [0x87, 0xeb, 0xe7, 0xfb];
pub const IDENTITY_GET_IDENTITY_SELECTOR: [u8; 4] = [0xd4, 0xd3, 0x67, 0x1f];
pub const IDENTITY_IS_AUTHORIZED_SELECTOR: [u8; 4] = [0x96, 0xb0, 0x45, 0x3e];
pub const IDENTITY_IS_DELEGATE_AUTHORIZED_SELECTOR: [u8; 4] = [0x2b, 0xf5, 0x04, 0x89];
pub const IDENTITY_GET_DELEGATION_SELECTOR: [u8; 4] = [0x0d, 0xb9, 0xc9, 0x10];
pub const IDENTITY_GRANT_DELEGATION_SELECTOR: [u8; 4] = [0x49, 0x58, 0x95, 0xff];
pub const IDENTITY_REVOKE_DELEGATION_SELECTOR: [u8; 4] = [0xb2, 0x30, 0x56, 0x5f];

pub const BUCKET_GET_BUCKET_SELECTOR: [u8; 4] = [0x6c, 0x5d, 0xca, 0xd3];
pub const BUCKET_GET_OWNER_NONCE_SELECTOR: [u8; 4] = [0x7a, 0x1c, 0x13, 0x7b];
pub const BUCKET_GET_OWNER_CATALOG_ROOT_SELECTOR: [u8; 4] = [0x41, 0xe6, 0xc9, 0x81];
pub const BUCKET_CREATE_BUCKET_SELECTOR: [u8; 4] = [0xbb, 0xb9, 0xf7, 0x40];
pub const BUCKET_DELETE_BUCKET_SELECTOR: [u8; 4] = [0x36, 0x5e, 0x58, 0xd9];
pub const BUCKET_INCREMENT_ENCRYPTION_VERSION_SELECTOR: [u8; 4] = [0x55, 0xb8, 0x5e, 0xd6];
pub const BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_PUT_SELECTOR: [u8; 4] = [0x5c, 0x0b, 0x7e, 0xab];
pub const BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_DELETE_SELECTOR: [u8; 4] =
    [0x94, 0xbc, 0x4c, 0x0d];

pub const BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_PUT_CAS_SELECTOR: [u8; 4] =
    [0x1c, 0x30, 0x3f, 0x1f];
pub const BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_DELETE_CAS_SELECTOR: [u8; 4] =
    [0x74, 0x16, 0x08, 0xe1];

pub fn encode_identity_register_identity(
    access_key_hash: AccessKeyHash,
    encrypted_sigv4_secret: Vec<u8>,
    nonce: SecretNonce,
) -> Vec<u8> {
    let mut data = IDENTITY_REGISTER_IDENTITY_SELECTOR.to_vec();
    access_key_hash.encode_to(&mut data);
    encrypted_sigv4_secret.encode_to(&mut data);
    nonce.encode_to(&mut data);
    data
}

pub fn encode_identity_get_identity(access_key_hash: AccessKeyHash) -> Vec<u8> {
    let mut data = IDENTITY_GET_IDENTITY_SELECTOR.to_vec();
    access_key_hash.encode_to(&mut data);
    data
}

pub fn encode_identity_is_authorized(access_key_hash: AccessKeyHash, operation: u32) -> Vec<u8> {
    let mut data = IDENTITY_IS_AUTHORIZED_SELECTOR.to_vec();
    access_key_hash.encode_to(&mut data);
    operation.encode_to(&mut data);
    data
}

pub fn encode_identity_is_delegate_authorized(
    owner: AccountId32,
    delegate: AccountId32,
    operation: u32,
) -> Vec<u8> {
    let mut data = IDENTITY_IS_DELEGATE_AUTHORIZED_SELECTOR.to_vec();
    owner.encode_to(&mut data);
    delegate.encode_to(&mut data);
    operation.encode_to(&mut data);
    data
}

pub fn encode_identity_get_delegation(owner: AccountId32, delegate: AccountId32) -> Vec<u8> {
    let mut data = IDENTITY_GET_DELEGATION_SELECTOR.to_vec();
    owner.encode_to(&mut data);
    delegate.encode_to(&mut data);
    data
}

pub fn encode_identity_grant_delegation(
    delegate: AccountId32,
    allowed_operations: u32,
    expires_at: u64,
) -> Vec<u8> {
    let mut data = IDENTITY_GRANT_DELEGATION_SELECTOR.to_vec();
    delegate.encode_to(&mut data);
    allowed_operations.encode_to(&mut data);
    expires_at.encode_to(&mut data);
    data
}

pub fn encode_identity_revoke_delegation(delegate: AccountId32) -> Vec<u8> {
    let mut data = IDENTITY_REVOKE_DELEGATION_SELECTOR.to_vec();
    delegate.encode_to(&mut data);
    data
}

pub fn encode_bucket_create_bucket(
    owner: AccountId32,
    bucket_name_hash: BucketNameHash,
    is_private: bool,
    owner_signature: [u8; 64],
    owner_catalog_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_CREATE_BUCKET_SELECTOR.to_vec();
    owner.encode_to(&mut data);
    bucket_name_hash.encode_to(&mut data);
    is_private.encode_to(&mut data);
    owner_signature.encode_to(&mut data);
    owner_catalog_root.encode_to(&mut data);
    data
}

pub fn encode_bucket_delete_bucket(
    bucket_name_hash: BucketNameHash,
    owner_signature: [u8; 64],
    owner_catalog_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_DELETE_BUCKET_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    owner_signature.encode_to(&mut data);
    owner_catalog_root.encode_to(&mut data);
    data
}

pub fn encode_bucket_increment_encryption_version(
    bucket_name_hash: BucketNameHash,
    owner_signature: [u8; 64],
) -> Vec<u8> {
    let mut data = BUCKET_INCREMENT_ENCRYPTION_VERSION_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    owner_signature.encode_to(&mut data);
    data
}

pub fn encode_bucket_get_bucket(bucket_name_hash: BucketNameHash) -> Vec<u8> {
    let mut data = BUCKET_GET_BUCKET_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    data
}

pub fn encode_bucket_get_owner_nonce(owner: AccountId32) -> Vec<u8> {
    let mut data = BUCKET_GET_OWNER_NONCE_SELECTOR.to_vec();
    owner.encode_to(&mut data);
    data
}

pub fn encode_bucket_get_owner_catalog_root(owner: AccountId32) -> Vec<u8> {
    let mut data = BUCKET_GET_OWNER_CATALOG_ROOT_SELECTOR.to_vec();
    owner.encode_to(&mut data);
    data
}

pub fn encode_bucket_update_bucket_manifest_root_for_put(
    bucket_name_hash: BucketNameHash,
    bucket_manifest_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_PUT_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    bucket_manifest_root.encode_to(&mut data);
    data
}

pub fn encode_bucket_update_bucket_manifest_root_for_delete(
    bucket_name_hash: BucketNameHash,
    bucket_manifest_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_DELETE_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    bucket_manifest_root.encode_to(&mut data);
    data
}

pub fn encode_bucket_update_bucket_manifest_root_for_put_cas(
    bucket_name_hash: BucketNameHash,
    expected_bucket_manifest_root: Vec<u8>,
    bucket_manifest_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_PUT_CAS_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    expected_bucket_manifest_root.encode_to(&mut data);
    bucket_manifest_root.encode_to(&mut data);
    data
}

pub fn encode_bucket_update_bucket_manifest_root_for_delete_cas(
    bucket_name_hash: BucketNameHash,
    expected_bucket_manifest_root: Vec<u8>,
    bucket_manifest_root: Vec<u8>,
) -> Vec<u8> {
    let mut data = BUCKET_UPDATE_BUCKET_MANIFEST_ROOT_FOR_DELETE_CAS_SELECTOR.to_vec();
    bucket_name_hash.encode_to(&mut data);
    expected_bucket_manifest_root.encode_to(&mut data);
    bucket_manifest_root.encode_to(&mut data);
    data
}

pub fn decode_query_result<T: Decode>(
    data: &[u8],
) -> Result<QueryResult<T>, parity_scale_codec::Error> {
    let mut input = &data[..];
    QueryResult::<T>::decode(&mut input)
}

pub fn decode_exec_result<T: Decode, E: Decode>(
    data: &[u8],
) -> Result<ExecResult<T, E>, parity_scale_codec::Error> {
    let mut input = &data[..];
    ExecResult::<T, E>::decode(&mut input)
}
