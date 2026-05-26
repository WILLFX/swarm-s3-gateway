#!/usr/bin/env python3
from pathlib import Path

handler = Path("trustless-proxy/src/http_handler.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessHttpHandler",
    "LocalTrustlessHttpHandlerPreparedResponse",
    "LocalTrustlessHttpHandlerCompletion",
    "LocalTrustlessHttpHandlerError",
    "LocalTrustlessHttpMapper::request_to_local_input",
    "LocalTrustlessRuntime::prepare_request",
    "LocalTrustlessHttpMapper::response_from_envelope",
    "LocalTrustlessRuntime::complete_get_with_plaintext",
    "prepare_http_request",
    "complete_get_with_plaintext",
    "gateway_plaintext_access: false",
]

required_tests = [
    "http_handler_prepares_put_as_pending_ciphertext_remote_http_response",
    "http_handler_prepares_get_as_pending_local_decrypt_http_response",
    "http_handler_completes_get_as_local_plaintext_http_response",
    "http_handler_prepares_head_delete_and_list_pending_responses",
    "http_handler_prepares_trustless_bucket_create_pending_anchor_response",
    "http_handler_rejects_plaintext_body_outside_put_object",
    "http_handler_rejects_unsupported_post_method",
    "http_handler_rejects_completing_non_get_as_plaintext",
]

required_lib = [
    "pub mod http_handler",
    "LocalTrustlessHttpHandler",
    "LocalTrustlessHttpHandlerPreparedResponse",
]

required_workflow = [
    "Check trustless local proxy HTTP handler surface",
    "./scripts/check_trustless_local_proxy_http_handler_surface.py",
]

for token in required_source:
    if token not in handler:
        raise SystemExit(f"FAILED: missing HTTP handler token: {token}")

for forbidden in [
    "TcpListener",
    "axum::",
    "hyper::",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in handler:
        raise SystemExit(f"FAILED: forbidden HTTP handler token: {forbidden}")

for token in required_tests:
    if token not in handler:
        raise SystemExit(f"FAILED: missing HTTP handler test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing HTTP handler lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing HTTP handler workflow token: {token}")

print("Trustless local proxy HTTP handler surface guard passed.")
