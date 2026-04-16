#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use codec::{Decode, Encode, MaxEncodedLen};
    use common::types::{AccessKeyHash, SubstrateAddress32};
    use frame_support::{
        dispatch::DispatchResult,
        pallet_prelude::*,
        traits::EnsureOrigin,
        BoundedVec,
    };
    use frame_system::{ensure_signed, pallet_prelude::*};
    use scale_info::TypeInfo;
    use frame_support::sp_runtime::traits::Convert;

    #[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, MaxEncodedLen, TypeInfo)]
    #[scale_info(skip_type_params(MaxEncryptedSecretLen))]
    pub struct IdentityEntry<MaxEncryptedSecretLen: Get<u32>> {
        pub owner: SubstrateAddress32,
        pub encrypted_sigv4_secret: BoundedVec<u8, MaxEncryptedSecretLen>,
        pub nonce: [u8; 12],
        pub key_version: u32,
        pub enabled: bool,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        type AccountIdToSubstrateAddress: Convert<Self::AccountId, SubstrateAddress32>;

        #[pallet::constant]
        type MaxEncryptedSecretLen: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn access_key_map)]
    pub type AccessKeyMap<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        AccessKeyHash,
        IdentityEntry<T::MaxEncryptedSecretLen>,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IdentityRegistered {
            access_key_hash: AccessKeyHash,
            owner: SubstrateAddress32,
            key_version: u32,
        },
        KeyRotated {
            access_key_hash: AccessKeyHash,
            owner: SubstrateAddress32,
            new_version: u32,
        },
        OwnerSetEnabled {
            access_key_hash: AccessKeyHash,
            owner: SubstrateAddress32,
            enabled: bool,
        },
        GovernanceRevoked {
            access_key_hash: AccessKeyHash,
            owner: SubstrateAddress32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        IdentityAlreadyExists,
        IdentityNotFound,
        IdentityAlreadyDisabled,
        NotAuthorized,
        EncryptedSecretTooLong,
        KeyVersionOverflow,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
        pub fn register_identity(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
            owner: SubstrateAddress32,
            encrypted_sigv4_secret: Vec<u8>,
            nonce: [u8; 12],
        ) -> DispatchResult {
            Self::ensure_owner_or_governance(origin, owner)?;

            ensure!(
                !AccessKeyMap::<T>::contains_key(access_key_hash),
                Error::<T>::IdentityAlreadyExists
            );

            let encrypted_sigv4_secret = Self::to_bounded_secret(encrypted_sigv4_secret)?;

            let entry = IdentityEntry::<T::MaxEncryptedSecretLen> {
                owner,
                encrypted_sigv4_secret,
                nonce,
                key_version: 1,
                enabled: true,
            };

            AccessKeyMap::<T>::insert(access_key_hash, entry);

            Self::deposit_event(Event::IdentityRegistered {
                access_key_hash,
                owner,
                key_version: 1,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
        pub fn rotate_key(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
            new_encrypted_sigv4_secret: Vec<u8>,
            new_nonce: [u8; 12],
        ) -> DispatchResult {
            let mut entry =
                AccessKeyMap::<T>::get(access_key_hash).ok_or(Error::<T>::IdentityNotFound)?;

            Self::ensure_owner_or_governance(origin, entry.owner)?;

            let new_version = entry
                .key_version
                .checked_add(1)
                .ok_or(Error::<T>::KeyVersionOverflow)?;

            entry.encrypted_sigv4_secret = Self::to_bounded_secret(new_encrypted_sigv4_secret)?;
            entry.nonce = new_nonce;
            entry.key_version = new_version;

            let owner = entry.owner;
            AccessKeyMap::<T>::insert(access_key_hash, entry);

            Self::deposit_event(Event::KeyRotated {
                access_key_hash,
                owner,
                new_version,
            });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
        pub fn owner_set_enabled(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
            status: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin).map_err(|_| Error::<T>::NotAuthorized)?;
            let caller_owner = T::AccountIdToSubstrateAddress::convert(who);

            let mut entry =
                AccessKeyMap::<T>::get(access_key_hash).ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(entry.owner == caller_owner, Error::<T>::NotAuthorized);

            entry.enabled = status;
            let owner = entry.owner;

            AccessKeyMap::<T>::insert(access_key_hash, entry);

            Self::deposit_event(Event::OwnerSetEnabled {
                access_key_hash,
                owner,
                enabled: status,
            });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().reads_writes(1, 1))]
        pub fn governance_revoke(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;

            let mut entry =
                AccessKeyMap::<T>::get(access_key_hash).ok_or(Error::<T>::IdentityNotFound)?;

            ensure!(entry.enabled, Error::<T>::IdentityAlreadyDisabled);

            entry.enabled = false;
            let owner = entry.owner;

            AccessKeyMap::<T>::insert(access_key_hash, entry);

            Self::deposit_event(Event::GovernanceRevoked {
                access_key_hash,
                owner,
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn ensure_owner_or_governance(
            origin: OriginFor<T>,
            owner: SubstrateAddress32,
        ) -> DispatchResult {
            if T::GovernanceOrigin::try_origin(origin.clone()).is_ok() {
                return Ok(());
            }

            let who = ensure_signed(origin).map_err(|_| Error::<T>::NotAuthorized)?;
            let caller_owner = T::AccountIdToSubstrateAddress::convert(who);

            ensure!(caller_owner == owner, Error::<T>::NotAuthorized);
            Ok(())
        }

        fn to_bounded_secret(
            secret: Vec<u8>,
        ) -> Result<BoundedVec<u8, T::MaxEncryptedSecretLen>, DispatchError> {
            secret
                .try_into()
                .map_err(|_| Error::<T>::EncryptedSecretTooLong.into())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate as chain_registry_pallet;
    use frame_support::{assert_noop, assert_ok, construct_runtime, derive_impl};
    use sp_runtime::{traits::Convert, BuildStorage};

    type Block = frame_system::mocking::MockBlock<Test>;

    construct_runtime!(
        pub enum Test {
            System: frame_system,
            Registry: chain_registry_pallet::{Pallet, Call, Storage, Event<T>},
        }
    );

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = Block;
    }

    struct AccountIdToSubstrateAddress;

    impl Convert<u64, SubstrateAddress32> for AccountIdToSubstrateAddress {
        fn convert(account: u64) -> SubstrateAddress32 {
            let mut out = [0u8; 32];
            out[..8].copy_from_slice(&account.to_le_bytes());
            out
        }
    }

    impl Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type GovernanceOrigin = frame_system::EnsureRoot<u64>;
        type AccountIdToSubstrateAddress = AccountIdToSubstrateAddress;
        type MaxEncryptedSecretLen = frame_support::traits::ConstU32<128>;
    }

    fn new_test_ext() -> sp_io::TestExternalities {
        let storage = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .expect("frame system storage should build");
        storage.into()
    }

    fn owner_of(account: u64) -> SubstrateAddress32 {
        AccountIdToSubstrateAddress::convert(account)
    }

    fn access_key_hash(byte: u8) -> AccessKeyHash {
        [byte; 32]
    }

    #[test]
    fn register_identity_by_owner_works() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(1);
            let owner = owner_of(1);
            let secret = vec![10u8, 20, 30, 40];
            let nonce = [9u8; 12];

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::signed(1),
                hash,
                owner,
                secret.clone(),
                nonce,
            ));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert_eq!(entry.owner, owner);
            assert_eq!(entry.encrypted_sigv4_secret.to_vec(), secret);
            assert_eq!(entry.nonce, nonce);
            assert_eq!(entry.key_version, 1);
            assert!(entry.enabled);
        });
    }

    #[test]
    fn governance_can_register_for_any_owner() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(2);
            let owner = owner_of(99);

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::root(),
                hash,
                owner,
                vec![1u8, 2, 3],
                [7u8; 12],
            ));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert_eq!(entry.owner, owner);
            assert_eq!(entry.key_version, 1);
            assert!(entry.enabled);
        });
    }

    #[test]
    fn non_owner_cannot_register_for_someone_else() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(3);
            let owner = owner_of(2);

            assert_noop!(
                Registry::register_identity(
                    RuntimeOrigin::signed(1),
                    hash,
                    owner,
                    vec![1u8, 2, 3],
                    [1u8; 12],
                ),
                Error::<Test>::NotAuthorized
            );
        });
    }

    #[test]
    fn rotate_key_updates_secret_nonce_and_version() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(4);
            let owner = owner_of(1);

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::signed(1),
                hash,
                owner,
                vec![1u8, 2, 3],
                [1u8; 12],
            ));

            assert_ok!(Registry::rotate_key(
                RuntimeOrigin::signed(1),
                hash,
                vec![8u8, 8, 8, 8],
                [2u8; 12],
            ));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert_eq!(entry.encrypted_sigv4_secret.to_vec(), vec![8u8, 8, 8, 8]);
            assert_eq!(entry.nonce, [2u8; 12]);
            assert_eq!(entry.key_version, 2);
            assert!(entry.enabled);
        });
    }

    #[test]
    fn owner_set_enabled_can_disable_and_re_enable() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(5);
            let owner = owner_of(1);

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::signed(1),
                hash,
                owner,
                vec![5u8, 5, 5],
                [3u8; 12],
            ));

            assert_ok!(Registry::owner_set_enabled(
                RuntimeOrigin::signed(1),
                hash,
                false,
            ));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert!(!entry.enabled);

            assert_ok!(Registry::owner_set_enabled(
                RuntimeOrigin::signed(1),
                hash,
                true,
            ));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert!(entry.enabled);
        });
    }

    #[test]
    fn non_owner_cannot_toggle_enabled() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(6);
            let owner = owner_of(1);

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::signed(1),
                hash,
                owner,
                vec![1u8],
                [4u8; 12],
            ));

            assert_noop!(
                Registry::owner_set_enabled(RuntimeOrigin::signed(2), hash, false),
                Error::<Test>::NotAuthorized
            );
        });
    }

    #[test]
    fn governance_revoke_disables_identity_and_second_revoke_fails() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(7);
            let owner = owner_of(1);

            assert_ok!(Registry::register_identity(
                RuntimeOrigin::signed(1),
                hash,
                owner,
                vec![9u8, 9],
                [5u8; 12],
            ));

            assert_ok!(Registry::governance_revoke(RuntimeOrigin::root(), hash));

            let entry = AccessKeyMap::<Test>::get(hash).expect("entry should exist");
            assert!(!entry.enabled);

            assert_noop!(
                Registry::governance_revoke(RuntimeOrigin::root(), hash),
                Error::<Test>::IdentityAlreadyDisabled
            );
        });
    }

    #[test]
    fn encrypted_secret_too_long_is_rejected() {
        new_test_ext().execute_with(|| {
            let hash = access_key_hash(8);
            let owner = owner_of(1);
            let oversized_secret = vec![42u8; 129];

            assert_noop!(
                Registry::register_identity(
                    RuntimeOrigin::signed(1),
                    hash,
                    owner,
                    oversized_secret,
                    [6u8; 12],
                ),
                Error::<Test>::EncryptedSecretTooLong
            );
        });
    }
}
