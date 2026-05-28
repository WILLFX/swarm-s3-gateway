#!/usr/bin/env python3
from pathlib import Path

source = Path("trustless-proxy/src/identity_recipient_resolver.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "IdentityContractEncryptionKeyRecord",
    "IdentityRecipientKeyReader",
    "IdentityContractRecipientKeyResolver",
    "IdentityRecipientKeyResolverConfig",
    "IdentityRecipientKeyResolverError",
    "identity_record_to_recipient_key_record",
    "RecipientKeyResolver for IdentityContractRecipientKeyResolver",
    "read_recipient_encryption_key",
    "aws-esdk-rust-recipient-key",
    "StaleKeyVersion",
    "KeyTypeMismatch",
    "AccountMismatch",
]

required_tests = [
    "identity_recipient_resolver_maps_enabled_contract_reads_to_recipient_records",
    "identity_recipient_resolver_fails_closed_when_contract_record_missing",
    "identity_recipient_resolver_fails_closed_when_contract_record_disabled",
    "identity_record_conversion_rejects_wrong_account",
    "identity_record_conversion_rejects_empty_public_key_or_key_type",
    "identity_record_conversion_rejects_invalid_utf8_key_type",
    "identity_record_conversion_rejects_wrong_key_type",
    "identity_record_conversion_rejects_stale_key_version",
    "identity_recipient_resolver_fails_closed_when_reader_fails",
]

required_lib = [
    "pub mod identity_recipient_resolver",
    "IdentityContractRecipientKeyResolver",
    "IdentityRecipientKeyReader",
]

required_workflow = [
    "Check trustless identity recipient resolver surface",
    "./scripts/check_trustless_identity_recipient_resolver_surface.py",
]

for token in required_source:
    if token not in source:
        raise SystemExit(f"FAILED: missing identity recipient resolver token: {token}")

for forbidden in [
    "silent_dev",
    "fallback_key",
    "dev_key",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "plaintext_private_key",
]:
    if forbidden in source:
        raise SystemExit(f"FAILED: forbidden identity recipient resolver token: {forbidden}")

for token in required_tests:
    if token not in source:
        raise SystemExit(f"FAILED: missing identity recipient resolver test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing identity recipient resolver lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing identity recipient resolver workflow token: {token}")

print("Trustless identity recipient resolver surface guard passed.")
