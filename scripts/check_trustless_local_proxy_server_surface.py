#!/usr/bin/env python3
from pathlib import Path

server = Path("trustless-proxy/src/server.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessServer",
    "LocalTrustlessServerConfig",
    "LocalTrustlessServerPreparedResponse",
    "LocalTrustlessServerCompletion",
    "LocalTrustlessServerError",
    "LocalTrustlessHttpHandler::prepare_http_request",
    "LocalTrustlessHttpHandler::complete_get_with_plaintext",
    "prepare_http_request",
    "complete_get_with_plaintext",
    "network_bind_enabled",
    "network_bind_performed: false",
    "gateway_plaintext_access: false",
]

required_tests = [
    "server_accepts_non_binding_local_config",
    "server_rejects_network_binding_in_scaffold",
    "server_rejects_invalid_config",
    "server_prepares_put_http_request_without_binding_network_socket",
    "server_prepares_get_http_request_as_pending_local_decrypt",
    "server_completes_get_with_local_plaintext_http_response",
    "server_prepares_trustless_bucket_create_without_remote_gateway",
    "server_rejects_plaintext_body_outside_put_boundary",
]

required_lib = [
    "pub mod server",
    "LocalTrustlessServer",
    "LocalTrustlessServerConfig",
]

required_workflow = [
    "Check trustless local proxy server surface",
    "./scripts/check_trustless_local_proxy_server_surface.py",
]

for token in required_source:
    if token not in server:
        raise SystemExit(f"FAILED: missing server token: {token}")

for forbidden in [
    "TcpListener",
    "axum::",
    "hyper::",
    "tokio::net",
    "std::net",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in server:
        raise SystemExit(f"FAILED: forbidden server token: {forbidden}")

for token in required_tests:
    if token not in server:
        raise SystemExit(f"FAILED: missing server test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing server lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing server workflow token: {token}")

print("Trustless local proxy server surface guard passed.")
