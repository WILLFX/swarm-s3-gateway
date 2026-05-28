#!/usr/bin/env python3
from pathlib import Path

source = Path("trustless-proxy/src/remote_gateway_http.rs").read_text()
remote_gateway = Path("trustless-proxy/src/remote_gateway.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
cargo = Path("trustless-proxy/Cargo.toml").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "RemoteGatewayHttpClient",
    "RemoteGatewayHttpClientConfig",
    "RemoteGatewayHttpTransport",
    "ReqwestRemoteGatewayHttpTransport",
    "TrustlessRemoteGatewayClient for RemoteGatewayHttpClient",
    "CiphertextGatewayRequest",
    "CiphertextGatewayResponse",
    "ciphertext_hex",
    "encrypted_manifest_hex",
    "PlaintextPayloadRejected",
    "GatewayPlaintextAccessRejected",
    "reqwest::blocking::Client",
    "/trustless/v1/ciphertext-gateway",
]

required_tests = [
    "http_client_sends_put_ciphertext_json_without_plaintext",
    "http_client_fetches_get_ciphertext_response",
    "http_client_fetches_encrypted_manifest_response",
    "http_client_sends_delete_encrypted_manifest_only",
    "http_client_rejects_plaintext_payload_before_transport",
    "http_client_rejects_response_claiming_gateway_plaintext_access",
    "http_client_rejects_invalid_base_url",
    "http_client_rejects_unknown_response_action",
]

required_lib = [
    "pub mod remote_gateway_http",
    "RemoteGatewayHttpClient",
    "ReqwestRemoteGatewayHttpTransport",
]

required_workflow = [
    "Check trustless remote gateway HTTP client surface",
    "./scripts/check_trustless_remote_gateway_http_client_surface.py",
]

for token in required_source:
    if token not in source:
        raise SystemExit(f"FAILED: missing remote gateway HTTP client token: {token}")

for forbidden in [
    "plaintext_payload:",
    "plaintext_body:",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "plaintext_private_key",
]:
    if forbidden in source:
        raise SystemExit(f"FAILED: forbidden remote gateway HTTP client token: {forbidden}")

for token in required_tests:
    if token not in source:
        raise SystemExit(f"FAILED: missing remote gateway HTTP client test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing remote gateway HTTP client lib token: {token}")

if "remote gateway HTTP client failed" not in remote_gateway:
    raise SystemExit("FAILED: missing RemoteGatewayClientError HTTP variant")

if "reqwest" not in cargo:
    raise SystemExit("FAILED: trustless-proxy missing reqwest dependency")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing remote gateway HTTP client workflow token: {token}")

print("Trustless remote gateway HTTP client surface guard passed.")
