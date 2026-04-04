#![allow(clippy::unused_unit)]

use crate::types::AccessKeyHash;
use frame_support::pallet_prelude::*;
use frame_system::pallet_prelude::*;
use scale_info::TypeInfo;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[derive(Clone, Encode, Decode, PartialEq, Eq, RuntimeDebug, TypeInfo, MaxEncodedLen)]
    pub struct RegistryEntry<AccountId, SecretBlob, NonceBlob> {
        pub owner: AccountId,
        pub encrypted_sigv4_secret: SecretBlob,
        pub nonce: NonceBlob,
        pub key_version: u32,
        pub enabled: bool,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Who may register / rotate / disable credentials.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        #[pallet::constant]
        type MaxSecretLen: Get<u32>;

        #[pallet::constant]
        type MaxNonceLen: Get<u32>;
    }

    pub type SecretBlobOf<T> = BoundedVec<u8, <T as Config>::MaxSecretLen>;
    pub type NonceBlobOf<T> = BoundedVec<u8, <T as Config>::MaxNonceLen>;
    pub type RegistryEntryOf<T> = RegistryEntry<
        <T as frame_system::Config>::AccountId,
        SecretBlobOf<T>,
        NonceBlobOf<T>,
    >;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Hashed_AWS_Access_Key -> Encrypted credential material + mapped owner
    #[pallet::storage]
    #[pallet::getter(fn credentials)]
    pub type Credentials<T: Config> =
        StorageMap<_, Blake2_128Concat, AccessKeyHash, RegistryEntryOf<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        CredentialRegistered {
            access_key_hash: AccessKeyHash,
            owner: T::AccountId,
            key_version: u32,
        },
        CredentialRotated {
            access_key_hash: AccessKeyHash,
            key_version: u32,
        },
        CredentialDisabled {
            access_key_hash: AccessKeyHash,
        },
        CredentialDeleted {
            access_key_hash: AccessKeyHash,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AlreadyExists,
        NotFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Initial registration of a Hashed_AWS_Access_Key -> (owner, encrypted secret)
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn register_credential(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
            owner: T::AccountId,
            encrypted_sigv4_secret: SecretBlobOf<T>,
            nonce: NonceBlobOf<T>,
            key_version: u32,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            ensure!(
                !Credentials::<T>::contains_key(access_key_hash),
                Error::<T>::AlreadyExists
            );

            let entry = RegistryEntry {
                owner: owner.clone(),
                encrypted_sigv4_secret,
                nonce,
                key_version,
                enabled: true,
            };

            Credentials::<T>::insert(access_key_hash, entry);

            Self::deposit_event(Event::CredentialRegistered {
                access_key_hash,
                owner,
                key_version,
            });

            Ok(())
        }

        /// Rotate the encrypted SigV4 secret blob in-place.
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn rotate_credential(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
            encrypted_sigv4_secret: SecretBlobOf<T>,
            nonce: NonceBlobOf<T>,
            key_version: u32,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            Credentials::<T>::try_mutate(access_key_hash, |maybe| -> DispatchResult {
                let entry = maybe.as_mut().ok_or(Error::<T>::NotFound)?;
                entry.encrypted_sigv4_secret = encrypted_sigv4_secret;
                entry.nonce = nonce;
                entry.key_version = key_version;
                entry.enabled = true;
                Ok(())
            })?;

            Self::deposit_event(Event::CredentialRotated {
                access_key_hash,
                key_version,
            });

            Ok(())
        }

        /// Disable a credential without deleting its on-chain record.
        #[pallet::call_index(2)]
        #[pallet::weight(10_000)]
        pub fn disable_credential(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            Credentials::<T>::try_mutate(access_key_hash, |maybe| -> DispatchResult {
                let entry = maybe.as_mut().ok_or(Error::<T>::NotFound)?;
                entry.enabled = false;
                Ok(())
            })?;

            Self::deposit_event(Event::CredentialDisabled { access_key_hash });
            Ok(())
        }

        /// Remove a credential entry completely.
        #[pallet::call_index(3)]
        #[pallet::weight(10_000)]
        pub fn delete_credential(
            origin: OriginFor<T>,
            access_key_hash: AccessKeyHash,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;

            ensure!(
                Credentials::<T>::contains_key(access_key_hash),
                Error::<T>::NotFound
            );

            Credentials::<T>::remove(access_key_hash);

            Self::deposit_event(Event::CredentialDeleted { access_key_hash });
            Ok(())
        }
    }
}

pub use pallet::*;
