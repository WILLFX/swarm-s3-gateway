use crate as chain_registry_pallet;
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::ConstU32,
};
use sp_runtime::{
    traits::{BuildStorage, IdentityLookup},
};

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
    pub enum Test {
        System: frame_system,
        ChainRegistry: chain_registry_pallet,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
}

parameter_types! {
    pub const MaxSecretLen: u32 = 256;
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxSecretLen = MaxSecretLen;
    type GovernanceOrigin = frame_system::EnsureRoot<u64>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .expect("frame_system storage builds");

    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| {
        System::set_block_number(1);
    });
    ext
}
