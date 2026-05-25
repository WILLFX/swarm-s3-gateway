#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod s3_identity_contract {
    use ink::prelude::vec::Vec;
    use ink::storage::Mapping;
    use s3_contracts_common::{
        AccountId32, DelegationEntry, EncryptionKeyRecord, IdentityRecord, OP_ALL,
    };

    #[derive(scale::Encode, scale::Decode, scale_info::TypeInfo, Debug, PartialEq, Eq)]
    pub enum Error {
        IdentityAlreadyExists,
        IdentityNotFound,
        IdentityAlreadyDisabled,
        NotAuthorized,
        DelegationExpired,
        InsufficientScope,
        UpgradeFailed,
        KeyVersionOverflow,
        EncryptionKeyAlreadyExists,
        EncryptionKeyNotFound,
        EncryptionKeyAlreadyDisabled,
        EncryptionPublicKeyEmpty,
        EncryptionKeyTypeEmpty,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    #[ink(storage)]
    pub struct S3IdentityContract {
        access_key_map: Mapping<[u8; 32], IdentityRecord>,
        delegation_map: Mapping<(AccountId32, AccountId32), DelegationEntry>,
        encryption_key_map: Mapping<AccountId32, EncryptionKeyRecord>,
        governance: AccountId,
    }

    impl S3IdentityContract {
        #[ink(constructor)]
        pub fn new(governance: AccountId) -> Self {
            Self {
                access_key_map: Mapping::default(),
                delegation_map: Mapping::default(),
                encryption_key_map: Mapping::default(),
                governance,
            }
        }

        #[ink(message)]
        pub fn register_identity(
            &mut self,
            access_key_hash: [u8; 32],
            encrypted_secret: Vec<u8>,
            nonce: [u8; 12],
        ) -> Result<()> {
            if self.access_key_map.get(access_key_hash).is_some() {
                return Err(Error::IdentityAlreadyExists);
            }

            let caller = Self::account_to_bytes(self.env().caller());
            let record = IdentityRecord {
                owner: caller,
                encrypted_sigv4_secret: encrypted_secret,
                nonce,
                key_version: 1,
                enabled: true,
            };

            self.access_key_map.insert(access_key_hash, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn rotate_key(
            &mut self,
            access_key_hash: [u8; 32],
            new_secret: Vec<u8>,
            new_nonce: [u8; 12],
        ) -> Result<()> {
            let mut record = match self.access_key_map.get(access_key_hash) {
                Some(record) => record,
                None => return Err(Error::IdentityNotFound),
            };

            let caller = Self::account_to_bytes(self.env().caller());
            let owner = record.owner;

            if caller != owner {
                self.ensure_delegate_scope(owner, caller, OP_ALL)?;
            }

            let next_version = match record.key_version.checked_add(1) {
                Some(v) => v,
                None => return Err(Error::KeyVersionOverflow),
            };

            record.encrypted_sigv4_secret = new_secret;
            record.nonce = new_nonce;
            record.key_version = next_version;

            self.access_key_map.insert(access_key_hash, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn owner_set_enabled(&mut self, access_key_hash: [u8; 32], status: bool) -> Result<()> {
            let mut record = match self.access_key_map.get(access_key_hash) {
                Some(record) => record,
                None => return Err(Error::IdentityNotFound),
            };

            let caller = Self::account_to_bytes(self.env().caller());
            if caller != record.owner {
                return Err(Error::NotAuthorized);
            }

            record.enabled = status;
            self.access_key_map.insert(access_key_hash, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn governance_revoke(&mut self, access_key_hash: [u8; 32]) -> Result<()> {
            self.ensure_governance(self.env().caller())?;

            let mut record = match self.access_key_map.get(access_key_hash) {
                Some(record) => record,
                None => return Err(Error::IdentityNotFound),
            };

            if !record.enabled {
                return Err(Error::IdentityAlreadyDisabled);
            }

            record.enabled = false;
            self.access_key_map.insert(access_key_hash, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn grant_delegation(
            &mut self,
            delegate: AccountId,
            allowed_operations: u32,
            expires_at: u64,
        ) -> Result<()> {
            let owner = Self::account_to_bytes(self.env().caller());
            let delegate = Self::account_to_bytes(delegate);

            let entry = DelegationEntry {
                delegate,
                allowed_operations,
                expires_at,
            };

            self.delegation_map.insert((owner, delegate), &entry);
            Ok(())
        }

        #[ink(message)]
        pub fn revoke_delegation(&mut self, delegate: AccountId) -> Result<()> {
            let owner = Self::account_to_bytes(self.env().caller());
            let delegate = Self::account_to_bytes(delegate);
            self.delegation_map.remove((owner, delegate));
            Ok(())
        }

        #[ink(message)]
        pub fn get_identity(&self, access_key_hash: [u8; 32]) -> Option<IdentityRecord> {
            self.access_key_map.get(access_key_hash)
        }

        #[ink(message)]
        pub fn is_authorized(&self, access_key_hash: [u8; 32], _operation: u32) -> bool {
            match self.access_key_map.get(access_key_hash) {
                Some(record) => record.enabled,
                None => false,
            }
        }

        #[ink(message)]
        pub fn is_delegate_authorized(
            &self,
            owner: AccountId32,
            delegate: AccountId32,
            operation: u32,
        ) -> bool {
            let entry = match self.delegation_map.get((owner, delegate)) {
                Some(entry) => entry,
                None => return false,
            };

            if self.env().block_timestamp() > entry.expires_at {
                return false;
            }

            (entry.allowed_operations & operation) == operation
        }

        #[ink(message)]
        pub fn get_delegation(
            &self,
            owner: AccountId32,
            delegate: AccountId32,
        ) -> Option<DelegationEntry> {
            self.delegation_map.get((owner, delegate))
        }

        #[ink(message)]
        pub fn register_encryption_key(
            &mut self,
            public_key: Vec<u8>,
            key_type: Vec<u8>,
        ) -> Result<()> {
            Self::ensure_non_empty_encryption_key_material(&public_key, &key_type)?;

            let owner = Self::account_to_bytes(self.env().caller());

            if self.encryption_key_map.get(owner).is_some() {
                return Err(Error::EncryptionKeyAlreadyExists);
            }

            let record = EncryptionKeyRecord {
                owner,
                public_key,
                key_type,
                key_version: 1,
                enabled: true,
                updated_at: self.env().block_timestamp(),
            };

            self.encryption_key_map.insert(owner, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn rotate_encryption_key(
            &mut self,
            public_key: Vec<u8>,
            key_type: Vec<u8>,
        ) -> Result<()> {
            Self::ensure_non_empty_encryption_key_material(&public_key, &key_type)?;

            let owner = Self::account_to_bytes(self.env().caller());

            let mut record = match self.encryption_key_map.get(owner) {
                Some(record) => record,
                None => return Err(Error::EncryptionKeyNotFound),
            };

            let next_version = match record.key_version.checked_add(1) {
                Some(v) => v,
                None => return Err(Error::KeyVersionOverflow),
            };

            record.public_key = public_key;
            record.key_type = key_type;
            record.key_version = next_version;
            record.enabled = true;
            record.updated_at = self.env().block_timestamp();

            self.encryption_key_map.insert(owner, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn disable_encryption_key(&mut self) -> Result<()> {
            let owner = Self::account_to_bytes(self.env().caller());

            let mut record = match self.encryption_key_map.get(owner) {
                Some(record) => record,
                None => return Err(Error::EncryptionKeyNotFound),
            };

            if !record.enabled {
                return Err(Error::EncryptionKeyAlreadyDisabled);
            }

            record.enabled = false;
            record.updated_at = self.env().block_timestamp();

            self.encryption_key_map.insert(owner, &record);
            Ok(())
        }

        #[ink(message)]
        pub fn get_encryption_key(&self, owner: AccountId32) -> Option<EncryptionKeyRecord> {
            self.encryption_key_map.get(owner)
        }

        #[ink(message)]
        pub fn governance(&self) -> AccountId {
            self.governance
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

        fn ensure_non_empty_encryption_key_material(
            public_key: &[u8],
            key_type: &[u8],
        ) -> Result<()> {
            if public_key.is_empty() {
                return Err(Error::EncryptionPublicKeyEmpty);
            }

            if key_type.is_empty() {
                return Err(Error::EncryptionKeyTypeEmpty);
            }

            Ok(())
        }

        fn ensure_governance(&self, caller: AccountId) -> Result<()> {
            if caller == self.governance {
                return Ok(());
            }
            Err(Error::NotAuthorized)
        }

        fn ensure_delegate_scope(
            &self,
            owner: AccountId32,
            delegate: AccountId32,
            operation: u32,
        ) -> Result<()> {
            let entry = match self.delegation_map.get((owner, delegate)) {
                Some(entry) => entry,
                None => return Err(Error::NotAuthorized),
            };

            if self.env().block_timestamp() > entry.expires_at {
                return Err(Error::DelegationExpired);
            }

            if (entry.allowed_operations & operation) != operation {
                return Err(Error::InsufficientScope);
            }

            Ok(())
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

        fn sample_hash(n: u8) -> [u8; 32] {
            [n; 32]
        }

        #[ink::test]
        fn register_identity_sets_owner_and_enabled() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);

            assert_eq!(c.register_identity(hash, vec![1, 2, 3], [4; 12]), Ok(()));

            let got = c.get_identity(hash);
            assert!(got.is_some());

            if let Some(record) = got {
                assert_eq!(record.owner, account_bytes(1));
                assert_eq!(record.key_version, 1);
                assert!(record.enabled);
            }
        }

        #[ink::test]
        fn governance_revoke_then_owner_reenable_works() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));

            set_caller(governance);
            assert_eq!(c.governance_revoke(hash), Ok(()));
            assert!(!c.is_authorized(hash, 0));

            set_caller(account(1));
            assert_eq!(c.owner_set_enabled(hash, true), Ok(()));
            assert!(c.is_authorized(hash, 0));
        }

        #[ink::test]
        fn governance_revoke_fails_if_already_disabled() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));

            set_caller(governance);
            assert_eq!(c.governance_revoke(hash), Ok(()));
            assert_eq!(
                c.governance_revoke(hash),
                Err(Error::IdentityAlreadyDisabled)
            );
        }

        #[ink::test]
        fn delegation_scope_and_expiry_are_enforced() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            assert_eq!(
                c.grant_delegation(account(2), s3_contracts_common::OP_GET_OBJECT, 100),
                Ok(())
            );

            set_timestamp(50);
            assert!(c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_GET_OBJECT
            ));
            assert!(!c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_DELETE_OBJECT
            ));

            set_timestamp(101);
            assert!(!c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_GET_OBJECT
            ));
        }

        #[ink::test]
        fn rotate_key_allows_full_scope_delegate() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));
            assert_eq!(c.grant_delegation(account(2), OP_ALL, 1_000), Ok(()));

            set_timestamp(10);
            set_caller(account(2));
            assert_eq!(c.rotate_key(hash, vec![9, 9], [8; 12]), Ok(()));

            let got = c.get_identity(hash);
            assert!(got.is_some());
            if let Some(record) = got {
                assert_eq!(record.key_version, 2);
                assert_eq!(record.encrypted_sigv4_secret, vec![9, 9]);
            }
        }

        #[ink::test]
        fn rotate_key_rejects_insufficient_scope_delegate() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));
            assert_eq!(
                c.grant_delegation(account(2), s3_contracts_common::OP_GET_OBJECT, 1_000),
                Ok(())
            );

            set_timestamp(10);
            set_caller(account(2));
            assert_eq!(
                c.rotate_key(hash, vec![9, 9], [8; 12]),
                Err(Error::InsufficientScope)
            );
        }

        #[ink::test]
        fn revoke_delegation_removes_authorization_and_record() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            assert_eq!(
                c.grant_delegation(account(2), s3_contracts_common::OP_PUT_OBJECT, 1_000),
                Ok(())
            );

            set_timestamp(10);
            assert!(c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_PUT_OBJECT
            ));
            assert!(
                c.get_delegation(account_bytes(1), account_bytes(2))
                    .is_some()
            );

            assert_eq!(c.revoke_delegation(account(2)), Ok(()));

            assert!(!c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_PUT_OBJECT
            ));
            assert!(
                c.get_delegation(account_bytes(1), account_bytes(2))
                    .is_none()
            );
        }

        #[ink::test]
        fn delegation_expiry_boundary_is_inclusive() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            assert_eq!(
                c.grant_delegation(account(2), s3_contracts_common::OP_GET_OBJECT, 100),
                Ok(())
            );

            set_timestamp(100);
            assert!(
                c.is_delegate_authorized(
                    account_bytes(1),
                    account_bytes(2),
                    s3_contracts_common::OP_GET_OBJECT
                ),
                "delegation should remain valid at exactly expires_at"
            );

            set_timestamp(101);
            assert!(
                !c.is_delegate_authorized(
                    account_bytes(1),
                    account_bytes(2),
                    s3_contracts_common::OP_GET_OBJECT
                ),
                "delegation should expire after expires_at"
            );
        }

        #[ink::test]
        fn composite_scope_requires_all_requested_bits() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            let allowed = s3_contracts_common::OP_GET_OBJECT | s3_contracts_common::OP_HEAD_OBJECT;

            set_caller(account(1));
            assert_eq!(c.grant_delegation(account(2), allowed, 1_000), Ok(()));

            set_timestamp(10);
            assert!(c.is_delegate_authorized(account_bytes(1), account_bytes(2), allowed));
            assert!(c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_GET_OBJECT
            ));
            assert!(!c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_DELETE_OBJECT
            ));
            assert!(!c.is_delegate_authorized(
                account_bytes(1),
                account_bytes(2),
                s3_contracts_common::OP_GET_OBJECT | s3_contracts_common::OP_DELETE_OBJECT
            ));
        }

        #[ink::test]
        fn rotate_key_rejects_expired_full_scope_delegate() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));
            assert_eq!(c.grant_delegation(account(2), OP_ALL, 10), Ok(()));

            set_timestamp(11);
            set_caller(account(2));
            assert_eq!(
                c.rotate_key(hash, vec![9, 9], [8; 12]),
                Err(Error::DelegationExpired)
            );
        }

        #[ink::test]
        fn rotate_key_rejects_missing_delegate() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            let hash = sample_hash(7);
            assert_eq!(c.register_identity(hash, vec![1], [2; 12]), Ok(()));

            set_timestamp(10);
            set_caller(account(2));
            assert_eq!(
                c.rotate_key(hash, vec![9, 9], [8; 12]),
                Err(Error::NotAuthorized)
            );
        }

        #[ink::test]
        fn register_encryption_key_sets_caller_record() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_timestamp(123);
            set_caller(account(1));

            assert_eq!(
                c.register_encryption_key(vec![1, 2, 3], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            let got = c.get_encryption_key(account_bytes(1));
            assert!(got.is_some());

            if let Some(record) = got {
                assert_eq!(record.owner, account_bytes(1));
                assert_eq!(record.public_key, vec![1, 2, 3]);
                assert_eq!(record.key_type, b"aws-esdk-custom-v1".to_vec());
                assert_eq!(record.key_version, 1);
                assert!(record.enabled);
                assert_eq!(record.updated_at, 123);
            }
        }

        #[ink::test]
        fn register_encryption_key_rejects_duplicate() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));

            assert_eq!(
                c.register_encryption_key(vec![1], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            assert_eq!(
                c.register_encryption_key(vec![2], b"aws-esdk-custom-v1".to_vec()),
                Err(Error::EncryptionKeyAlreadyExists)
            );
        }

        #[ink::test]
        fn register_encryption_key_rejects_empty_material() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));

            assert_eq!(
                c.register_encryption_key(Vec::new(), b"aws-esdk-custom-v1".to_vec()),
                Err(Error::EncryptionPublicKeyEmpty)
            );

            assert_eq!(
                c.register_encryption_key(vec![1], Vec::new()),
                Err(Error::EncryptionKeyTypeEmpty)
            );
        }

        #[ink::test]
        fn rotate_encryption_key_increments_version_and_reenables() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_timestamp(100);
            set_caller(account(1));

            assert_eq!(
                c.register_encryption_key(vec![1], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            assert_eq!(c.disable_encryption_key(), Ok(()));

            set_timestamp(200);
            assert_eq!(
                c.rotate_encryption_key(vec![2, 3], b"aws-esdk-custom-v2".to_vec()),
                Ok(())
            );

            let got = c.get_encryption_key(account_bytes(1));
            assert!(got.is_some());

            if let Some(record) = got {
                assert_eq!(record.public_key, vec![2, 3]);
                assert_eq!(record.key_type, b"aws-esdk-custom-v2".to_vec());
                assert_eq!(record.key_version, 2);
                assert!(record.enabled);
                assert_eq!(record.updated_at, 200);
            }
        }

        #[ink::test]
        fn rotate_encryption_key_rejects_missing_record() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));

            assert_eq!(
                c.rotate_encryption_key(vec![1], b"aws-esdk-custom-v1".to_vec()),
                Err(Error::EncryptionKeyNotFound)
            );
        }

        #[ink::test]
        fn disable_encryption_key_marks_record_disabled() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_timestamp(100);
            set_caller(account(1));

            assert_eq!(
                c.register_encryption_key(vec![1], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            set_timestamp(150);
            assert_eq!(c.disable_encryption_key(), Ok(()));

            let got = c.get_encryption_key(account_bytes(1));
            assert!(got.is_some());

            if let Some(record) = got {
                assert!(!record.enabled);
                assert_eq!(record.updated_at, 150);
            }

            assert_eq!(
                c.disable_encryption_key(),
                Err(Error::EncryptionKeyAlreadyDisabled)
            );
        }

        #[ink::test]
        fn encryption_key_records_are_account_scoped() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            assert_eq!(
                c.register_encryption_key(vec![1], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            set_caller(account(2));
            assert_eq!(
                c.register_encryption_key(vec![2], b"aws-esdk-custom-v1".to_vec()),
                Ok(())
            );

            assert_eq!(
                c.get_encryption_key(account_bytes(1)).unwrap().public_key,
                vec![1]
            );
            assert_eq!(
                c.get_encryption_key(account_bytes(2)).unwrap().public_key,
                vec![2]
            );
        }

        #[ink::test]
        fn only_governance_can_change_governance() {
            let governance = account(9);
            let mut c = S3IdentityContract::new(governance);

            set_caller(account(1));
            assert_eq!(c.set_governance(account(8)), Err(Error::NotAuthorized));

            set_caller(governance);
            assert_eq!(c.set_governance(account(8)), Ok(()));
            assert_eq!(c.governance(), account(8));
        }
    }
}
