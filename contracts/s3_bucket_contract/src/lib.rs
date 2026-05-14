#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod s3_bucket_contract {
    use ink::{
        env::{call::FromAccountId, sr25519_verify},
        prelude::vec::Vec,
        storage::Mapping,
    };
    use s3_contracts_common::{
        AccountId32, BucketRecord, DelegationEntry, OP_CREATE_BUCKET, OP_DELETE_BUCKET,
        OP_DELETE_OBJECT, OP_PUT_OBJECT, S3IdentityRead,
    };

    #[derive(scale::Encode, scale::Decode, scale_info::TypeInfo, Debug, PartialEq, Eq)]
    pub enum Error {
        BucketAlreadyExists,
        BucketNotFound,
        NotAuthorized,
        InvalidSignature,
        EncryptionVersionOverflow,
        DelegationExpired,
        InsufficientScope,
        UpgradeFailed,
        NonceOverflow,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    #[ink(event)]
    pub struct BucketCreated {
        #[ink(topic)]
        hash: [u8; 32],
        #[ink(topic)]
        owner: AccountId,
        is_private: bool,
    }

    #[ink(event)]
    pub struct BucketDeleted {
        #[ink(topic)]
        hash: [u8; 32],
        #[ink(topic)]
        owner: AccountId32,
    }

    #[ink(event)]
    pub struct EncryptionVersionIncremented {
        #[ink(topic)]
        hash: [u8; 32],
        new_version: u32,
    }

    #[ink(event)]
    pub struct BucketManifestRootUpdated {
        #[ink(topic)]
        hash: [u8; 32],
        #[ink(topic)]
        owner: AccountId32,
        bucket_manifest_root: Vec<u8>,
    }

    #[ink(event)]
    pub struct OwnerCatalogRootUpdated {
        #[ink(topic)]
        owner: AccountId32,
        owner_catalog_root: Vec<u8>,
    }

    #[ink(storage)]
    pub struct S3BucketContract {
        bucket_map: Mapping<[u8; 32], BucketRecord>,
        owner_nonces: Mapping<AccountId32, u64>,
        owner_catalog_roots: Mapping<AccountId32, Vec<u8>>,
        identity_contract: AccountId,
        governance: AccountId,
    }

    impl S3BucketContract {
        #[ink(constructor)]
        pub fn new(governance: AccountId, identity_contract: AccountId) -> Self {
            Self {
                bucket_map: Mapping::default(),
                owner_nonces: Mapping::default(),
                owner_catalog_roots: Mapping::default(),
                identity_contract,
                governance,
            }
        }

        #[ink(message)]
        pub fn create_bucket(
            &mut self,
            owner: AccountId,
            bucket_name_hash: [u8; 32],
            is_private: bool,
            owner_signature: [u8; 64],
            owner_catalog_root: Vec<u8>,
        ) -> Result<()> {
            if self.bucket_map.get(bucket_name_hash).is_some() {
                return Err(Error::BucketAlreadyExists);
            }

            let owner_bytes = Self::account_to_bytes(owner);
            let nonce = self.get_owner_nonce(owner_bytes);

            self.verify_create_signature(
                owner_bytes,
                bucket_name_hash,
                is_private,
                nonce,
                owner_signature,
            )?;

            self.ensure_create_authorized(owner_bytes, self.env().caller())?;

            let record = BucketRecord {
                owner: owner_bytes,
                is_private,
                encryption_version: 1,
                creation_date: self.env().block_timestamp(),
                bucket_manifest_root: Vec::new(),
            };

            self.bucket_map.insert(bucket_name_hash, &record);
            self.owner_catalog_roots
                .insert(owner_bytes, &owner_catalog_root);
            self.bump_owner_nonce(owner_bytes)?;

            self.env().emit_event(OwnerCatalogRootUpdated {
                owner: owner_bytes,
                owner_catalog_root,
            });

            self.env().emit_event(BucketCreated {
                hash: bucket_name_hash,
                owner,
                is_private,
            });

            Ok(())
        }

        #[ink(message)]
        pub fn delete_bucket(
            &mut self,
            bucket_name_hash: [u8; 32],
            owner_signature: [u8; 64],
            owner_catalog_root: Vec<u8>,
        ) -> Result<()> {
            let record = match self.bucket_map.get(bucket_name_hash) {
                Some(record) => record,
                None => return Err(Error::BucketNotFound),
            };

            let owner = record.owner;
            let nonce = self.get_owner_nonce(owner);

            self.verify_delete_signature(owner, bucket_name_hash, nonce, owner_signature)?;
            self.ensure_delete_authorized(owner, self.env().caller())?;

            self.bucket_map.remove(bucket_name_hash);
            self.owner_catalog_roots.insert(owner, &owner_catalog_root);
            self.bump_owner_nonce(owner)?;

            self.env().emit_event(OwnerCatalogRootUpdated {
                owner,
                owner_catalog_root,
            });

            self.env().emit_event(BucketDeleted {
                hash: bucket_name_hash,
                owner,
            });

            Ok(())
        }

        #[ink(message)]
        pub fn increment_encryption_version(
            &mut self,
            bucket_name_hash: [u8; 32],
            owner_signature: [u8; 64],
        ) -> Result<()> {
            let mut record = match self.bucket_map.get(bucket_name_hash) {
                Some(record) => record,
                None => return Err(Error::BucketNotFound),
            };

            let owner = record.owner;
            let nonce = self.get_owner_nonce(owner);

            self.verify_increment_signature(owner, bucket_name_hash, nonce, owner_signature)?;
            self.ensure_increment_authorized(owner, self.env().caller())?;

            let new_version = match record.encryption_version.checked_add(1) {
                Some(v) => v,
                None => return Err(Error::EncryptionVersionOverflow),
            };

            record.encryption_version = new_version;
            self.bucket_map.insert(bucket_name_hash, &record);
            self.bump_owner_nonce(owner)?;

            self.env().emit_event(EncryptionVersionIncremented {
                hash: bucket_name_hash,
                new_version,
            });

            Ok(())
        }

        #[ink(message)]
        pub fn update_bucket_manifest_root_for_put(
            &mut self,
            bucket_name_hash: [u8; 32],
            bucket_manifest_root: Vec<u8>,
        ) -> Result<()> {
            self.update_bucket_manifest_root_with_scope(
                bucket_name_hash,
                bucket_manifest_root,
                OP_PUT_OBJECT,
            )
        }

        #[ink(message)]
        pub fn update_bucket_manifest_root_for_delete(
            &mut self,
            bucket_name_hash: [u8; 32],
            bucket_manifest_root: Vec<u8>,
        ) -> Result<()> {
            self.update_bucket_manifest_root_with_scope(
                bucket_name_hash,
                bucket_manifest_root,
                OP_DELETE_OBJECT,
            )
        }

        #[ink(message)]
        pub fn get_owner_catalog_root(&self, owner: AccountId32) -> Vec<u8> {
            self.owner_catalog_roots.get(owner).unwrap_or_default()
        }

        #[ink(message)]
        pub fn get_bucket(&self, bucket_name_hash: [u8; 32]) -> Option<BucketRecord> {
            self.bucket_map.get(bucket_name_hash)
        }

        #[ink(message)]
        pub fn get_owner_nonce(&self, owner: AccountId32) -> u64 {
            self.owner_nonces.get(owner).unwrap_or(0)
        }

        #[ink(message)]
        pub fn governance(&self) -> AccountId {
            self.governance
        }

        #[ink(message)]
        pub fn identity_contract(&self) -> AccountId {
            self.identity_contract
        }

        #[ink(message)]
        pub fn set_governance(&mut self, new_governance: AccountId) -> Result<()> {
            self.ensure_governance(self.env().caller())?;
            self.governance = new_governance;
            Ok(())
        }

        #[ink(message)]
        pub fn set_code(&mut self, new_code_hash: Hash) -> Result<()> {
            self.ensure_governance(self.env().caller())?;
            match self.env().set_code_hash(&new_code_hash) {
                Ok(()) => Ok(()),
                Err(_) => Err(Error::UpgradeFailed),
            }
        }

        fn ensure_governance(&self, caller: AccountId) -> Result<()> {
            if caller == self.governance {
                return Ok(());
            }
            Err(Error::NotAuthorized)
        }

        fn ensure_create_authorized(&self, owner: AccountId32, caller: AccountId) -> Result<()> {
            if caller == self.governance || Self::account_to_bytes(caller) == owner {
                return Ok(());
            }

            let entry = self.fetch_delegation(owner, Self::account_to_bytes(caller))?;
            Self::evaluate_delegation(&entry, self.env().block_timestamp(), OP_CREATE_BUCKET)
        }

        fn ensure_delete_authorized(&self, owner: AccountId32, caller: AccountId) -> Result<()> {
            if caller == self.governance || Self::account_to_bytes(caller) == owner {
                return Ok(());
            }

            let entry = self.fetch_delegation(owner, Self::account_to_bytes(caller))?;
            Self::evaluate_delegation(&entry, self.env().block_timestamp(), OP_DELETE_BUCKET)
        }

        fn ensure_increment_authorized(&self, owner: AccountId32, caller: AccountId) -> Result<()> {
            if Self::account_to_bytes(caller) == owner {
                return Ok(());
            }

            let entry = self.fetch_delegation(owner, Self::account_to_bytes(caller))?;
            Self::evaluate_delegation(&entry, self.env().block_timestamp(), OP_PUT_OBJECT)
        }

        fn ensure_object_operation_authorized(
            &self,
            owner: AccountId32,
            caller: AccountId,
            required_scope: u32,
        ) -> Result<()> {
            if Self::account_to_bytes(caller) == owner {
                return Ok(());
            }

            let entry = self.fetch_delegation(owner, Self::account_to_bytes(caller))?;
            Self::evaluate_delegation(&entry, self.env().block_timestamp(), required_scope)
        }

        fn update_bucket_manifest_root_with_scope(
            &mut self,
            bucket_name_hash: [u8; 32],
            bucket_manifest_root: Vec<u8>,
            required_scope: u32,
        ) -> Result<()> {
            let mut record = match self.bucket_map.get(bucket_name_hash) {
                Some(record) => record,
                None => return Err(Error::BucketNotFound),
            };

            let owner = record.owner;

            self.ensure_object_operation_authorized(owner, self.env().caller(), required_scope)?;

            record.bucket_manifest_root = bucket_manifest_root.clone();
            self.bucket_map.insert(bucket_name_hash, &record);

            self.env().emit_event(BucketManifestRootUpdated {
                hash: bucket_name_hash,
                owner,
                bucket_manifest_root,
            });

            Ok(())
        }

        fn fetch_delegation(
            &self,
            owner: AccountId32,
            delegate: AccountId32,
        ) -> Result<DelegationEntry> {
            let identity: ink::contract_ref!(S3IdentityRead) =
                FromAccountId::from_account_id(self.identity_contract);

            match identity.get_delegation(owner, delegate) {
                Some(entry) => Ok(entry),
                None => Err(Error::NotAuthorized),
            }
        }

        fn evaluate_delegation(
            entry: &DelegationEntry,
            now: u64,
            required_scope: u32,
        ) -> Result<()> {
            if now > entry.expires_at {
                return Err(Error::DelegationExpired);
            }

            if (entry.allowed_operations & required_scope) != required_scope {
                return Err(Error::InsufficientScope);
            }

            Ok(())
        }

        fn bump_owner_nonce(&mut self, owner: AccountId32) -> Result<()> {
            let current = self.get_owner_nonce(owner);
            let next = match current.checked_add(1) {
                Some(v) => v,
                None => return Err(Error::NonceOverflow),
            };
            self.owner_nonces.insert(owner, &next);
            Ok(())
        }

        fn verify_create_signature(
            &self,
            owner: AccountId32,
            bucket_name_hash: [u8; 32],
            is_private: bool,
            owner_nonce: u64,
            owner_signature: [u8; 64],
        ) -> Result<()> {
            let mut payload = self.domain_payload(b"s3gw/v1/create_bucket", bucket_name_hash);
            payload.push(if is_private { 1 } else { 0 });
            payload.extend_from_slice(&owner_nonce.to_le_bytes());
            self.verify_sr25519(owner, &payload, owner_signature)
        }

        fn verify_delete_signature(
            &self,
            owner: AccountId32,
            bucket_name_hash: [u8; 32],
            owner_nonce: u64,
            owner_signature: [u8; 64],
        ) -> Result<()> {
            let mut payload = self.domain_payload(b"s3gw/v1/delete_bucket", bucket_name_hash);
            payload.extend_from_slice(&owner_nonce.to_le_bytes());
            self.verify_sr25519(owner, &payload, owner_signature)
        }

        fn verify_increment_signature(
            &self,
            owner: AccountId32,
            bucket_name_hash: [u8; 32],
            owner_nonce: u64,
            owner_signature: [u8; 64],
        ) -> Result<()> {
            let mut payload =
                self.domain_payload(b"s3gw/v1/increment_encryption_version", bucket_name_hash);
            payload.extend_from_slice(&owner_nonce.to_le_bytes());
            self.verify_sr25519(owner, &payload, owner_signature)
        }

        fn domain_payload(&self, operation_tag: &[u8], bucket_name_hash: [u8; 32]) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(operation_tag);
            payload.extend_from_slice(self.env().account_id().as_ref());
            payload.extend_from_slice(&bucket_name_hash);
            payload
        }

        fn verify_sr25519(
            &self,
            owner: AccountId32,
            payload: &[u8],
            owner_signature: [u8; 64],
        ) -> Result<()> {
            match sr25519_verify(&owner_signature, payload, &owner) {
                Ok(()) => Ok(()),
                Err(_) => Err(Error::InvalidSignature),
            }
        }

        fn account_to_bytes(account: AccountId) -> AccountId32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(account.as_ref());
            out
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::{self, test};
        use sp_core::Pair;
        use sp_core::sr25519;

        fn set_caller(caller: AccountId) {
            test::set_caller::<env::DefaultEnvironment>(caller);
        }

        fn set_timestamp(ts: u64) {
            test::set_block_timestamp::<env::DefaultEnvironment>(ts);
        }

        fn account(n: u8) -> AccountId {
            AccountId::from([n; 32])
        }

        fn account_bytes(n: u8) -> AccountId32 {
            [n; 32]
        }

        fn hash(n: u8) -> [u8; 32] {
            [n; 32]
        }

        fn account_bytes_from_pair(pair: &sr25519::Pair) -> AccountId32 {
            pair.public().0
        }

        fn account_from_pair(pair: &sr25519::Pair) -> AccountId {
            AccountId::from(pair.public().0)
        }

        fn create_payload(
            contract: &S3BucketContract,
            bucket_name_hash: [u8; 32],
            is_private: bool,
            nonce: u64,
        ) -> Vec<u8> {
            let mut payload = contract.domain_payload(b"s3gw/v1/create_bucket", bucket_name_hash);
            payload.push(if is_private { 1 } else { 0 });
            payload.extend_from_slice(&nonce.to_le_bytes());
            payload
        }

        fn delete_payload(
            contract: &S3BucketContract,
            bucket_name_hash: [u8; 32],
            nonce: u64,
        ) -> Vec<u8> {
            let mut payload = contract.domain_payload(b"s3gw/v1/delete_bucket", bucket_name_hash);
            payload.extend_from_slice(&nonce.to_le_bytes());
            payload
        }

        fn increment_payload(
            contract: &S3BucketContract,
            bucket_name_hash: [u8; 32],
            nonce: u64,
        ) -> Vec<u8> {
            let mut payload =
                contract.domain_payload(b"s3gw/v1/increment_encryption_version", bucket_name_hash);
            payload.extend_from_slice(&nonce.to_le_bytes());
            payload
        }

        #[ink::test]
        fn create_bucket_rejects_invalid_signature() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            let pair = sr25519::Pair::from_seed(&[1u8; 32]);
            let owner = account_from_pair(&pair);

            set_caller(owner);

            let bad_sig = [0u8; 64];
            assert_eq!(
                c.create_bucket(owner, hash(1), true, bad_sig),
                Err(Error::InvalidSignature)
            );
        }

        #[ink::test]
        fn create_bucket_with_valid_owner_signature_works() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            let pair = sr25519::Pair::from_seed(&[1u8; 32]);
            let owner = account_from_pair(&pair);
            let owner_bytes = account_bytes_from_pair(&pair);

            set_caller(owner);

            let nonce = c.get_owner_nonce(owner_bytes);
            let payload = create_payload(&c, hash(1), true, nonce);
            let sig = pair.sign(&payload);

            assert_eq!(c.create_bucket(owner, hash(1), true, sig.0), Ok(()));

            let got = c.get_bucket(hash(1));
            assert!(got.is_some());
            if let Some(record) = got {
                assert_eq!(record.owner, owner_bytes);
                assert!(record.is_private);
                assert_eq!(record.encryption_version, 1);
            }
        }

        #[ink::test]
        fn delete_bucket_replay_signature_fails_after_nonce_bump() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            let pair = sr25519::Pair::from_seed(&[1u8; 32]);
            let owner = account_from_pair(&pair);
            let owner_bytes = account_bytes_from_pair(&pair);

            set_caller(owner);

            let create_nonce = c.get_owner_nonce(owner_bytes);
            let create_sig = pair.sign(&create_payload(&c, hash(1), false, create_nonce));
            assert_eq!(c.create_bucket(owner, hash(1), false, create_sig.0), Ok(()));

            let delete_nonce = c.get_owner_nonce(owner_bytes);
            let delete_sig = pair.sign(&delete_payload(&c, hash(1), delete_nonce));
            assert_eq!(c.delete_bucket(hash(1), delete_sig.0), Ok(()));

            assert_eq!(
                c.delete_bucket(hash(1), delete_sig.0),
                Err(Error::BucketNotFound)
            );
        }

        #[ink::test]
        fn governance_can_delete_with_valid_owner_signature() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            let pair = sr25519::Pair::from_seed(&[1u8; 32]);
            let owner = account_from_pair(&pair);
            let owner_bytes = account_bytes_from_pair(&pair);

            set_caller(owner);
            let create_nonce = c.get_owner_nonce(owner_bytes);
            let create_sig = pair.sign(&create_payload(&c, hash(1), false, create_nonce));
            assert_eq!(c.create_bucket(owner, hash(1), false, create_sig.0), Ok(()));

            let delete_nonce = c.get_owner_nonce(owner_bytes);
            let delete_sig = pair.sign(&delete_payload(&c, hash(1), delete_nonce));

            set_caller(governance);
            assert_eq!(c.delete_bucket(hash(1), delete_sig.0), Ok(()));
        }

        #[ink::test]
        fn increment_signature_replay_is_rejected() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            let pair = sr25519::Pair::from_seed(&[1u8; 32]);
            let owner = account_from_pair(&pair);
            let owner_bytes = account_bytes_from_pair(&pair);

            set_caller(owner);
            let create_nonce = c.get_owner_nonce(owner_bytes);
            let create_sig = pair.sign(&create_payload(&c, hash(1), false, create_nonce));
            assert_eq!(c.create_bucket(owner, hash(1), false, create_sig.0), Ok(()));

            let nonce = c.get_owner_nonce(owner_bytes);
            let sig = pair.sign(&increment_payload(&c, hash(1), nonce));
            assert_eq!(c.increment_encryption_version(hash(1), sig.0), Ok(()));

            assert_eq!(
                c.increment_encryption_version(hash(1), sig.0),
                Err(Error::InvalidSignature)
            );
        }

        #[ink::test]
        fn evaluate_delegation_detects_expiry_and_scope() {
            set_timestamp(50);

            let ok = DelegationEntry {
                delegate: account_bytes(2),
                allowed_operations: OP_CREATE_BUCKET | OP_PUT_OBJECT,
                expires_at: 100,
            };
            assert_eq!(
                S3BucketContract::evaluate_delegation(&ok, 50, OP_CREATE_BUCKET),
                Ok(())
            );

            let expired = DelegationEntry {
                delegate: account_bytes(2),
                allowed_operations: OP_CREATE_BUCKET,
                expires_at: 10,
            };
            assert_eq!(
                S3BucketContract::evaluate_delegation(&expired, 50, OP_CREATE_BUCKET),
                Err(Error::DelegationExpired)
            );

            let scoped = DelegationEntry {
                delegate: account_bytes(2),
                allowed_operations: s3_contracts_common::OP_GET_OBJECT,
                expires_at: 100,
            };
            assert_eq!(
                S3BucketContract::evaluate_delegation(&scoped, 50, OP_CREATE_BUCKET),
                Err(Error::InsufficientScope)
            );
        }

        #[ink::test]
        fn only_governance_can_change_governance() {
            let governance = account(9);
            let identity = account(8);
            let mut c = S3BucketContract::new(governance, identity);

            set_caller(account(1));
            assert_eq!(c.set_governance(account(7)), Err(Error::NotAuthorized));

            set_caller(governance);
            assert_eq!(c.set_governance(account(7)), Ok(()));
            assert_eq!(c.governance(), account(7));
        }
    }
}
