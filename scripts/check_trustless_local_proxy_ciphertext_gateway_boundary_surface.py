#!/usr/bin/env python3
from pathlib import Path

boundary = Path("trustless-proxy/src/gateway_boundary.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "CiphertextGatewayBoundary",
    "CiphertextGatewayRequest",
    "CiphertextGatewayResponse",
    "CiphertextGatewayBoundaryError",
    "put_ciphertext_request",
    "get_ciphertext_request",
    "head_ciphertext_request",
    "list_encrypted_manifest_request",
    "delete_ciphertext_request",
    "validate_response",
    "ciphertext_payload",
    "encrypted_manifest_payload",
    "plaintext_payload_present: false",
    "PlaintextPayloadRejected",
    "GatewayPlaintextAccessRejected",
]

required_tests = [
    "put_request_forwards_ciphertext_only_payload",
    "get_and_head_requests_never_include_plaintext_payloads",
    "list_request_fetches_encrypted_manifest_without_plaintext_payload",
    "delete_request_forwards_only_encrypted_manifest_payload",
    "boundary_rejects_empty_payloads_for_ciphertext_forwarding",
    "boundary_rejects_routes_that_allow_plaintext_or_non_ciphertext_remote",
    "boundary_rejects_responses_that_claim_gateway_plaintext_access",
]

required_lib = [
    "pub mod gateway_boundary",
    "CiphertextGatewayBoundary",
    "CiphertextGatewayRequest",
]

required_workflow = [
    "Check trustless local proxy ciphertext gateway boundary surface",
    "./scripts/check_trustless_local_proxy_ciphertext_gateway_boundary_surface.py",
]

for token in required_source:
    if token not in boundary:
        raise SystemExit(f"FAILED: missing trustless ciphertext gateway boundary token: {token}")

for forbidden in [
    "plaintext_payload: Vec",
    "send_plaintext",
    "decrypt_at_gateway",
    "gateway_plaintext_payload",
]:
    if forbidden in boundary:
        raise SystemExit(f"FAILED: forbidden trustless gateway boundary token: {forbidden}")

for token in required_tests:
    if token not in boundary:
        raise SystemExit(f"FAILED: missing trustless ciphertext gateway boundary test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless ciphertext gateway boundary lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless ciphertext gateway boundary workflow token: {token}")

print("Trustless local proxy ciphertext gateway boundary surface guard passed.")
