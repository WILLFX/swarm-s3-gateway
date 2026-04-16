use crate::{mock::*, AccessKeyMap, Error, Event};
use frame_support::{assert_noop, assert_ok, BoundedVec};

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn nonce(byte: u8) -> [u8; 12] {
    [byte; 12]
}

fn secret(data: &[u8]) -> BoundedVec<u8, <Test as crate::Config>::MaxSecretLen> {
    data.to_vec()
        .try_into()
        .expect("test secret fits within MaxSecretLen")
}

#[test]
fn register_identity_works() {
    new_test_ext().execute_with(|| {
        let owner = 1u64;
        let key_hash = hash(7);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"encrypted-secret-v1"),
            nonce(9),
        ));

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert_eq!(entry.owner, owner);
        assert_eq!(entry.nonce, nonce(9));
        assert_eq!(entry.key_version, 1);
        assert!(entry.is_enabled);

        System::assert_last_event(RuntimeEvent::ChainRegistry(
            Event::IdentityRegistered {
                hash: key_hash,
                owner,
            },
        ));
    });
}

#[test]
fn register_identity_fails_when_already_registered() {
    new_test_ext().execute_with(|| {
        let owner = 1u64;
        let key_hash = hash(3);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"first-secret"),
            nonce(1),
        ));

        assert_noop!(
            ChainRegistry::register_identity(
                RuntimeOrigin::signed(owner),
                key_hash,
                secret(b"second-secret"),
                nonce(2),
            ),
            Error::<Test>::IdentityAlreadyRegistered
        );
    });
}

#[test]
fn rotate_key_works_for_owner_and_increments_version() {
    new_test_ext().execute_with(|| {
        let owner = 10u64;
        let key_hash = hash(11);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_ok!(ChainRegistry::rotate_key(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v2"),
            nonce(2),
        ));

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert_eq!(entry.owner, owner);
        assert_eq!(entry.nonce, nonce(2));
        assert_eq!(entry.encrypted_secret, secret(b"secret-v2"));
        assert_eq!(entry.key_version, 2);
        assert!(entry.is_enabled);

        System::assert_last_event(RuntimeEvent::ChainRegistry(
            Event::KeyRotated {
                hash: key_hash,
                new_version: 2,
            },
        ));
    });
}

#[test]
fn rotate_key_fails_for_non_owner() {
    new_test_ext().execute_with(|| {
        let owner = 10u64;
        let attacker = 99u64;
        let key_hash = hash(12);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_noop!(
            ChainRegistry::rotate_key(
                RuntimeOrigin::signed(attacker),
                key_hash,
                secret(b"secret-v2"),
                nonce(2),
            ),
            Error::<Test>::NotOwner
        );

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert_eq!(entry.encrypted_secret, secret(b"secret-v1"));
        assert_eq!(entry.nonce, nonce(1));
        assert_eq!(entry.key_version, 1);
    });
}

#[test]
fn owner_set_enabled_works() {
    new_test_ext().execute_with(|| {
        let owner = 20u64;
        let key_hash = hash(13);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_ok!(ChainRegistry::owner_set_enabled(
            RuntimeOrigin::signed(owner),
            key_hash,
            false,
        ));

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert!(!entry.is_enabled);

        System::assert_last_event(RuntimeEvent::ChainRegistry(
            Event::IdentityStatusChanged {
                hash: key_hash,
                is_enabled: false,
            },
        ));
    });
}

#[test]
fn owner_set_enabled_fails_for_non_owner() {
    new_test_ext().execute_with(|| {
        let owner = 20u64;
        let other = 21u64;
        let key_hash = hash(14);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_noop!(
            ChainRegistry::owner_set_enabled(
                RuntimeOrigin::signed(other),
                key_hash,
                false,
            ),
            Error::<Test>::NotOwner
        );

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert!(entry.is_enabled);
    });
}

#[test]
fn governance_revoke_works_for_root() {
    new_test_ext().execute_with(|| {
        let owner = 30u64;
        let key_hash = hash(15);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_ok!(ChainRegistry::governance_revoke(
            RuntimeOrigin::root(),
            key_hash,
        ));

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert!(!entry.is_enabled);

        System::assert_last_event(RuntimeEvent::ChainRegistry(
            Event::IdentityRevoked { hash: key_hash },
        ));
    });
}

#[test]
fn governance_revoke_fails_for_non_governance_origin() {
    new_test_ext().execute_with(|| {
        let owner = 30u64;
        let key_hash = hash(16);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_noop!(
            ChainRegistry::governance_revoke(
                RuntimeOrigin::signed(owner),
                key_hash,
            ),
            Error::<Test>::NotAuthorized
        );

        let entry = AccessKeyMap::<Test>::get(key_hash).expect("entry must exist");
        assert!(entry.is_enabled);
    });
}

#[test]
fn governance_revoke_fails_when_already_disabled() {
    new_test_ext().execute_with(|| {
        let owner = 30u64;
        let key_hash = hash(17);

        assert_ok!(ChainRegistry::register_identity(
            RuntimeOrigin::signed(owner),
            key_hash,
            secret(b"secret-v1"),
            nonce(1),
        ));

        assert_ok!(ChainRegistry::governance_revoke(
            RuntimeOrigin::root(),
            key_hash,
        ));

        assert_noop!(
            ChainRegistry::governance_revoke(
                RuntimeOrigin::root(),
                key_hash,
            ),
            Error::<Test>::AlreadyDisabled
        );
    });
}
