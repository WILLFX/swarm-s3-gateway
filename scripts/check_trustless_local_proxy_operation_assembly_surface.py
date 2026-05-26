#!/usr/bin/env python3
from pathlib import Path

operations = Path("trustless-proxy/src/operations.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessOperationAssembler",
    "TrustlessPutOperationInput",
    "TrustlessPutOperationPlan",
    "TrustlessDeleteOperationInput",
    "TrustlessDeleteOperationPlan",
    "TrustlessOperationError",
    "prepare_put",
    "prepare_get_request",
    "complete_get_response",
    "prepare_list_request",
    "complete_list_response",
    "prepare_delete",
    "TrustlessEncryptionBoundary",
    "TrustlessManifestBoundary",
    "CiphertextGatewayBoundary",
    "remote_payloads_are_ciphertext_only: true",
    "gateway_plaintext_access: false",
]

required_tests = [
    "put_operation_encrypts_object_and_manifest_locally",
    "get_operation_prepares_ciphertext_request_and_decrypts_response_locally",
    "list_operation_fetches_encrypted_manifest_and_lists_metadata_locally",
    "delete_operation_updates_and_encrypts_manifest_locally",
    "operation_assembly_rejects_missing_ciphertext_or_manifest_responses",
    "operation_assembly_rejects_gateway_plaintext_response",
]

required_lib = [
    "pub mod operations",
    "TrustlessOperationAssembler",
    "TrustlessPutOperationInput",
]

required_workflow = [
    "Check trustless local proxy operation assembly surface",
    "./scripts/check_trustless_local_proxy_operation_assembly_surface.py",
]

for token in required_source:
    if token not in operations:
        raise SystemExit(f"FAILED: missing trustless operation assembly token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_decrypt",
    "plaintext_remote_payload",
]:
    if forbidden in operations:
        raise SystemExit(f"FAILED: forbidden trustless operation assembly token: {forbidden}")

for token in required_tests:
    if token not in operations:
        raise SystemExit(f"FAILED: missing trustless operation assembly test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless operation assembly lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless operation assembly workflow token: {token}")

print("Trustless local proxy operation assembly surface guard passed.")
