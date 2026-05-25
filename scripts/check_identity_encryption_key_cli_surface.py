#!/usr/bin/env python3
from pathlib import Path

abi = Path("gateway/src/contracts_abi.rs").read_text()
cli_path = Path("gateway/src/bin/identity_encryption_key.rs")

if not cli_path.exists():
    raise SystemExit("FAILED: identity_encryption_key CLI is missing")

cli = cli_path.read_text()

required_abi = [
    "IDENTITY_REGISTER_ENCRYPTION_KEY_SELECTOR",
    "IDENTITY_ROTATE_ENCRYPTION_KEY_SELECTOR",
    "IDENTITY_DISABLE_ENCRYPTION_KEY_SELECTOR",
    "[0x89, 0x85, 0x48, 0x3c]",
    "[0x1b, 0x11, 0x67, 0xbb]",
    "[0xc7, 0x7a, 0xba, 0x06]",
    "encode_identity_register_encryption_key",
    "encode_identity_rotate_encryption_key",
    "encode_identity_disable_encryption_key",
    "encode_identity_encryption_key_write_selectors_match_metadata",
    "Error12",
]

required_cli = [
    "S3GW_IDENTITY_KEY_SIGNER_SURI",
    "identity_encryption_key register <public_key_hex> <key_type>",
    "encode_identity_register_encryption_key",
    "encode_identity_rotate_encryption_key",
    "encode_identity_disable_encryption_key",
    "dry_run_gas_required",
    "identity encryption key command completed successfully",
]

for token in required_abi:
    if token not in abi:
        raise SystemExit(f"FAILED: missing identity encryption-key CLI ABI token: {token}")

for token in required_cli:
    if token not in cli:
        raise SystemExit(f"FAILED: missing identity encryption-key CLI token: {token}")

for forbidden in ["//Alice", "//Bob", "unwrap_or_else"]:
    if forbidden in cli:
        raise SystemExit(f"FAILED: identity encryption-key CLI contains fallback/dev signer token: {forbidden}")

print("Identity encryption key CLI surface guard passed.")
