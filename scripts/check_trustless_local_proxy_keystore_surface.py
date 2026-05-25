#!/usr/bin/env python3
from pathlib import Path

keystore = Path("trustless-proxy/src/local_keystore.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalKeyRequest",
    "LocalKeystoreRecord",
    "LocalPrivateKeySelection",
    "LocalKeystoreResolver",
    "LocalPrivateKeySelector",
    "LocalKeystoreError",
    "encrypted_private_key_blob",
    "MissingEnabledLocalPrivateKey",
    "EmptyEncryptedPrivateKeyBlob",
    "EmptyStorageLabel",
    "select_enabled_key",
]

required_tests = [
    "selector_picks_highest_enabled_local_private_key_version",
    "selector_fails_closed_when_no_enabled_key_exists",
    "selector_rejects_empty_encrypted_private_key_blob",
    "selector_rejects_empty_storage_label",
    "selector_rejects_missing_account_or_key_type",
    "selection_exposes_only_encrypted_private_key_blob_not_plaintext_key",
]

required_lib = [
    "pub mod local_keystore",
    "LocalPrivateKeySelector",
    "LocalKeystoreResolver",
]

required_workflow = [
    "Check trustless local proxy keystore surface",
    "./scripts/check_trustless_local_proxy_keystore_surface.py",
]

for token in required_source:
    if token not in keystore:
        raise SystemExit(f"FAILED: missing trustless local keystore source token: {token}")

for forbidden in ["plaintext_private_key", "raw_private_key"]:
    if forbidden in keystore:
        raise SystemExit(f"FAILED: trustless local keystore must not expose token: {forbidden}")

for token in required_tests:
    if token not in keystore:
        raise SystemExit(f"FAILED: missing trustless local keystore test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless local keystore lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless local keystore workflow token: {token}")

print("Trustless local proxy keystore surface guard passed.")
