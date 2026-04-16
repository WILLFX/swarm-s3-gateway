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
    use sp_runtime::traits::Convert;

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
