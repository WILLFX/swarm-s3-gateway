#!/usr/bin/env python3
from pathlib import Path

references = Path("trustless-proxy/src/references.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessReferenceModel",
    "TrustlessObjectReferenceInput",
    "TrustlessObjectReference",
    "TrustlessRemoteObjectReference",
    "EncryptedManifestReference",
    "TrustlessReferenceError",
    "plaintext_key_stays_local",
    "gateway_plaintext_access",
    "object_reference",
    "remote_object_reference",
    "manifest_entry",
    "object_reference_from_manifest_entry",
    "encrypted_manifest_reference",
    "encrypted_manifest_only: true",
    "gateway_plaintext_access: false",
]

required_tests = [
    "object_reference_keeps_plaintext_key_local_and_gateway_ciphertext_only",
    "remote_object_reference_excludes_plaintext_object_key",
    "manifest_entry_roundtrip_preserves_local_metadata",
    "encrypted_manifest_reference_is_encrypted_only",
    "reference_model_rejects_missing_fields_and_empty_ciphertext",
    "reference_model_rejects_gateway_plaintext_access",
]

required_lib = [
    "pub mod references",
    "TrustlessReferenceModel",
    "TrustlessRemoteObjectReference",
]

required_workflow = [
    "Check trustless local proxy reference model surface",
    "./scripts/check_trustless_local_proxy_reference_model_surface.py",
]

for token in required_source:
    if token not in references:
        raise SystemExit(f"FAILED: missing trustless reference model token: {token}")

for forbidden in [
    "gateway_plaintext_object_key",
    "send_plaintext_key_to_gateway",
    "plaintext_remote_object_key",
]:
    if forbidden in references:
        raise SystemExit(f"FAILED: forbidden trustless reference token: {forbidden}")

for token in required_tests:
    if token not in references:
        raise SystemExit(f"FAILED: missing trustless reference model test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless reference model lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless reference model workflow token: {token}")

print("Trustless local proxy reference model surface guard passed.")
