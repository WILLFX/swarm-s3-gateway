#!/usr/bin/env python3
from pathlib import Path

source = Path("trustless-proxy/src/chain_recipient_key_adapter.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
cargo = Path("trustless-proxy/Cargo.toml").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "ChainRecipientAccountMapping",
    "ChainRecipientEncryptionKeyLookup",
    "ChainRecipientKeyReader",
    "ChainRecipientKeyAdapterError",
    "ChainEncryptionKeyRecord",
    "SubstrateAddress32",
    "IdentityRecipientKeyReader for ChainRecipientKeyReader",
    "chain_record_to_identity_record",
    "OwnerMismatch",
    "MissingOwnerForAccount",
]

required_tests = [
    "chain_recipient_key_reader_maps_chain_records_into_identity_resolver",
    "chain_recipient_key_reader_fails_closed_when_account_mapping_missing",
    "chain_recipient_key_reader_fails_closed_when_chain_record_missing",
    "chain_recipient_key_reader_fails_closed_when_chain_record_disabled",
    "chain_record_to_identity_record_rejects_owner_mismatch",
    "chain_recipient_key_reader_rejects_empty_account_mapping",
    "chain_recipient_key_reader_fails_closed_when_lookup_errors",
]

required_lib = [
    "pub mod chain_recipient_key_adapter",
    "ChainRecipientKeyReader",
    "ChainRecipientEncryptionKeyLookup",
]

required_workflow = [
    "Check trustless chain recipient key adapter surface",
    "./scripts/check_trustless_chain_recipient_key_adapter_surface.py",
]

for token in required_source:
    if token not in source:
        raise SystemExit(f"FAILED: missing chain recipient adapter token: {token}")

for forbidden in [
    "silent_dev",
    "fallback_key",
    "dev_key",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "plaintext_private_key",
]:
    if forbidden in source:
        raise SystemExit(f"FAILED: forbidden chain recipient adapter token: {forbidden}")

for token in required_tests:
    if token not in source:
        raise SystemExit(f"FAILED: missing chain recipient adapter test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing chain recipient adapter lib token: {token}")

if "common =" not in cargo:
    raise SystemExit("FAILED: trustless-proxy missing common dependency")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing chain recipient adapter workflow token: {token}")

print("Trustless chain recipient key adapter surface guard passed.")
