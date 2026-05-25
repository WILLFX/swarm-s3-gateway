#!/usr/bin/env python3
from pathlib import Path

common = Path("common/src/types.rs").read_text()
abi = Path("gateway/src/contracts_abi.rs").read_text()
registry = Path("gateway/src/chain/registry.rs").read_text()

required_common = [
    "pub struct ChainEncryptionKeyRecord",
    "pub public_key: Vec<u8>",
    "pub key_type: Vec<u8>",
    "pub updated_at: u64",
]

required_abi = [
    "pub struct EncryptionKeyRecord",
    "IDENTITY_GET_ENCRYPTION_KEY_SELECTOR",
    "[0xb1, 0xde, 0x34, 0x37]",
    "pub fn encode_identity_get_encryption_key",
    "encode_identity_get_encryption_key_uses_metadata_selector",
    "encryption_key_record_scale_roundtrip_works",
]

required_registry = [
    "ChainEncryptionKeyRecord",
    "ContractEncryptionKeyRecord",
    "encode_identity_get_encryption_key",
    "pub async fn get_encryption_key",
    "identity::get_encryption_key",
]

for token in required_common:
    if token not in common:
        raise SystemExit(f"FAILED: missing common encryption-key read token: {token}")

for token in required_abi:
    if token not in abi:
        raise SystemExit(f"FAILED: missing ABI encryption-key read token: {token}")

for token in required_registry:
    if token not in registry:
        raise SystemExit(f"FAILED: missing registry encryption-key read token: {token}")

print("Gateway encryption key registry read surface guard passed.")
