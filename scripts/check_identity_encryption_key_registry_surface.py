#!/usr/bin/env python3
from pathlib import Path

common = Path("contracts/common/src/lib.rs").read_text()
identity = Path("contracts/s3_identity_contract/src/lib.rs").read_text()

required_common = [
    "pub struct EncryptionKeyRecord",
    "pub public_key: Vec<u8>",
    "pub key_type: Vec<u8>",
    "pub key_version: u32",
    "pub updated_at: u64",
    "fn get_encryption_key(&self, owner: AccountId32) -> Option<EncryptionKeyRecord>",
]

required_identity = [
    "encryption_key_map: Mapping<AccountId32, EncryptionKeyRecord>",
    "pub fn register_encryption_key",
    "pub fn rotate_encryption_key",
    "pub fn disable_encryption_key",
    "pub fn get_encryption_key",
    "EncryptionKeyAlreadyExists",
    "EncryptionKeyNotFound",
    "EncryptionPublicKeyEmpty",
    "EncryptionKeyTypeEmpty",
    "register_encryption_key_sets_caller_record",
    "rotate_encryption_key_increments_version_and_reenables",
    "encryption_key_records_are_account_scoped",
]

for token in required_common:
    if token not in common:
        raise SystemExit(f"FAILED: missing common encryption-key registry token: {token}")

for token in required_identity:
    if token not in identity:
        raise SystemExit(f"FAILED: missing identity encryption-key registry token: {token}")

print("Identity encryption key registry surface guard passed.")
