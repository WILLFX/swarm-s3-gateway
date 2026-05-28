#!/usr/bin/env python3
from pathlib import Path

source = Path("trustless-proxy/src/local_keystore_file.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalKeystoreFile",
    "LocalKeystoreFileDocument",
    "LocalKeystoreFileRecord",
    "LocalKeystoreFileError",
    "encrypted_private_key_hex",
    "LocalPrivateKeySelection",
    "encode_records",
    "decode_records",
    "write_records",
    "read_records",
    "load_private_key_selection",
    "s3w.trustless.local-keystore",
]

required_tests = [
    "local_keystore_file_encodes_encrypted_records_without_plaintext_key_fields",
    "local_keystore_file_round_trips_records_deterministically",
    "local_keystore_file_writes_and_reads_records_from_disk",
    "local_keystore_file_loads_highest_enabled_private_key_selection",
    "local_keystore_file_rejects_empty_or_malformed_file",
    "local_keystore_file_rejects_unsupported_schema_version",
    "local_keystore_file_rejects_missing_fields_or_empty_blob",
    "local_keystore_file_rejects_malformed_encrypted_private_key_hex",
    "local_keystore_file_rejects_missing_enabled_selection",
]

required_lib = [
    "pub mod local_keystore_file",
    "LocalKeystoreFile",
    "LocalKeystoreFileError",
]

required_workflow = [
    "Check trustless local keystore file surface",
    "./scripts/check_trustless_local_keystore_file_surface.py",
]

for token in required_source:
    if token not in source:
        raise SystemExit(f"FAILED: missing local keystore file token: {token}")

for forbidden in [
    "plaintext_private_key:",
    "raw_private_key:",
    "private_key_material:",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in source:
        raise SystemExit(f"FAILED: forbidden local keystore file token: {forbidden}")

for token in required_tests:
    if token not in source:
        raise SystemExit(f"FAILED: missing local keystore file test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing local keystore file lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing local keystore file workflow token: {token}")

print("Trustless local keystore file surface guard passed.")
