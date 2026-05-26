#!/usr/bin/env python3
from pathlib import Path

manifest = Path("trustless-proxy/src/manifest.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessManifestBoundary",
    "TrustlessManifestCipher",
    "TrustlessManifestEntry",
    "EncryptedTrustlessManifest",
    "decrypt_manifest_locally",
    "encrypt_manifest_locally",
    "upsert_entry_locally",
    "remove_entry_locally",
    "list_metadata_locally",
    "decrypted_locally: true",
    "encrypted_locally: true",
    "mutated_locally: true",
    "gateway_plaintext_access: false",
    "GatewayPlaintextAccessRejected",
]

required_tests = [
    "decrypt_manifest_locally_returns_manifest_without_gateway_plaintext_access",
    "encrypt_manifest_locally_returns_encrypted_manifest_only",
    "upsert_entry_locally_replaces_existing_entry_and_increments_version",
    "upsert_entry_locally_adds_new_entry_deterministically",
    "remove_entry_locally_removes_entry_and_fails_when_missing",
    "list_metadata_locally_uses_decrypted_manifest_entries_only",
    "manifest_boundary_rejects_empty_or_gateway_plaintext_inputs",
    "manifest_boundary_rejects_malformed_manifest_entries",
]

required_lib = [
    "pub mod manifest",
    "TrustlessManifestBoundary",
    "TrustlessManifestCipher",
]

required_workflow = [
    "Check trustless local proxy manifest boundary surface",
    "./scripts/check_trustless_local_proxy_manifest_boundary_surface.py",
]

for token in required_source:
    if token not in manifest:
        raise SystemExit(f"FAILED: missing trustless manifest boundary token: {token}")

for forbidden in [
    "gateway_decrypt_manifest",
    "send_plaintext_manifest",
    "plaintext_manifest_payload",
]:
    if forbidden in manifest:
        raise SystemExit(f"FAILED: forbidden trustless manifest boundary token: {forbidden}")

for token in required_tests:
    if token not in manifest:
        raise SystemExit(f"FAILED: missing trustless manifest boundary test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless manifest boundary lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless manifest boundary workflow token: {token}")

print("Trustless local proxy manifest boundary surface guard passed.")
