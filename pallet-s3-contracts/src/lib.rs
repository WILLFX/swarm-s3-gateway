#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*, traits::EnsureOrigin};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type GovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn identity_contract_address)]
    pub type IdentityContractAddress<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn bucket_contract_address)]
    pub type BucketContractAddress<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        IdentityContractAddressSet { address: T::AccountId },
        BucketContractAddressSet { address: T::AccountId },
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().writes(1))]
        pub fn set_identity_contract_address(
            origin: OriginFor<T>,
            address: T::AccountId,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            IdentityContractAddress::<T>::put(address.clone());
            Self::deposit_event(Event::IdentityContractAddressSet { address });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000, 0) + T::DbWeight::get().writes(1))]
        pub fn set_bucket_contract_address(
            origin: OriginFor<T>,
            address: T::AccountId,
        ) -> DispatchResult {
            T::GovernanceOrigin::ensure_origin(origin)?;
            BucketContractAddress::<T>::put(address.clone());
            Self::deposit_event(Event::BucketContractAddressSet { address });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate as pallet_s3_contracts;
    use frame_support::{
        assert_noop, assert_ok, construct_runtime, derive_impl,
        sp_runtime::{traits::IdentityLookup, BuildStorage},
    };

    type Block = frame_system::mocking::MockBlock<Test>;

    construct_runtime!(
        pub enum Test {
            System: frame_system,
            S3Contracts: pallet_s3_contracts::{Pallet, Call, Storage, Event<T>},
        }
    );

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = Block;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
    }

    impl pallet::Config for Test {
        type RuntimeEvent = RuntimeEvent;
        type GovernanceOrigin = frame_system::EnsureRoot<u64>;
    }

    fn new_test_ext() -> sp_io::TestExternalities {
        let storage = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .expect("frame_system storage builds");
        sp_io::TestExternalities::new(storage)
    }

    #[test]
    fn governance_can_set_identity_contract_address() {
        new_test_ext().execute_with(|| {
            assert_ok!(S3Contracts::set_identity_contract_address(
                RuntimeOrigin::root(),
                42
            ));
            assert_eq!(S3Contracts::identity_contract_address(), Some(42));
        });
    }

    #[test]
    fn governance_can_set_bucket_contract_address() {
        new_test_ext().execute_with(|| {
            assert_ok!(S3Contracts::set_bucket_contract_address(
                RuntimeOrigin::root(),
                77
            ));
            assert_eq!(S3Contracts::bucket_contract_address(), Some(77));
        });
    }

    #[test]
    fn non_governance_cannot_set_addresses() {
        new_test_ext().execute_with(|| {
            assert_noop!(
                S3Contracts::set_identity_contract_address(RuntimeOrigin::signed(1), 42),
                sp_runtime::DispatchError::BadOrigin
            );

            assert_noop!(
                S3Contracts::set_bucket_contract_address(RuntimeOrigin::signed(1), 77),
                sp_runtime::DispatchError::BadOrigin
            );
        });
    }
}
