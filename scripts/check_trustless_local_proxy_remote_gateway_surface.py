#!/usr/bin/env python3
from pathlib import Path

remote = Path("trustless-proxy/src/remote_gateway.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessRemoteGatewayClient",
    "TrustlessRemoteGatewayExecutor",
    "RemoteGatewayClientError",
    "execute_ciphertext_request",
    "CiphertextGatewayRequest",
    "CiphertextGatewayResponse",
    "PlaintextPayloadRejected",
    "MissingPutCiphertextPayload",
    "MissingDeleteEncryptedManifestPayload",
    "UnexpectedCiphertextPayload",
    "UnexpectedEncryptedManifestPayload",
    "GatewayPlaintextAccessRejected",
]

required_tests = [
    "executor_forwards_put_ciphertext_request_without_plaintext",
    "executor_forwards_get_request_without_payloads",
    "executor_forwards_delete_with_encrypted_manifest_only",
    "executor_rejects_plaintext_payload_flag_before_client_call",
    "executor_requires_put_ciphertext_payload",
    "executor_requires_delete_encrypted_manifest_payload",
    "executor_rejects_unexpected_payloads_for_read_requests",
    "executor_rejects_gateway_plaintext_response",
]

required_lib = [
    "pub mod remote_gateway",
    "TrustlessRemoteGatewayClient",
    "TrustlessRemoteGatewayExecutor",
]

required_workflow = [
    "Check trustless local proxy remote gateway surface",
    "./scripts/check_trustless_local_proxy_remote_gateway_surface.py",
]

for token in required_source:
    if token not in remote:
        raise SystemExit(f"FAILED: missing trustless remote gateway token: {token}")

for forbidden in [
    "plaintext_payload: Vec",
    "send_plaintext",
    "gateway_decrypt",
    "plaintext_remote_payload",
]:
    if forbidden in remote:
        raise SystemExit(f"FAILED: forbidden trustless remote gateway token: {forbidden}")

for token in required_tests:
    if token not in remote:
        raise SystemExit(f"FAILED: missing trustless remote gateway test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless remote gateway lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless remote gateway workflow token: {token}")

print("Trustless local proxy remote gateway surface guard passed.")
