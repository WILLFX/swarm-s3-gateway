#!/usr/bin/env python3
from pathlib import Path

handler = Path("trustless-proxy/src/handler.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessHandler",
    "LocalTrustlessHandlerPreparedResponse",
    "LocalTrustlessHandlerCompletion",
    "LocalTrustlessHandlerError",
    "LocalTrustlessRequestAdapter::prepare",
    "LocalTrustlessResponseAdapter::from_prepared_operation",
    "TrustlessLocalService::complete_get_with_plaintext",
    "LocalTrustlessResponseAdapter::from_execution_result",
    "prepare_request",
    "complete_get_with_plaintext",
    "gateway_plaintext_access: false",
]

required_tests = [
    "handler_prepares_put_as_pending_ciphertext_remote_response",
    "handler_prepares_get_as_pending_local_decrypt_response",
    "handler_completes_get_as_local_plaintext_response",
    "handler_prepares_delete_as_pending_ciphertext_remote_response",
    "handler_prepares_create_bucket_as_pending_anchor_response",
    "handler_prepares_list_without_object_key_id",
    "handler_rejects_plaintext_body_outside_put_boundary",
    "handler_rejects_completing_non_get_as_plaintext",
]

required_lib = [
    "pub mod handler",
    "LocalTrustlessHandler",
    "LocalTrustlessHandlerPreparedResponse",
]

required_workflow = [
    "Check trustless local proxy handler surface",
    "./scripts/check_trustless_local_proxy_handler_surface.py",
]

for token in required_source:
    if token not in handler:
        raise SystemExit(f"FAILED: missing local handler token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in handler:
        raise SystemExit(f"FAILED: forbidden local handler token: {forbidden}")

for token in required_tests:
    if token not in handler:
        raise SystemExit(f"FAILED: missing local handler test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing local handler lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing local handler workflow token: {token}")

print("Trustless local proxy handler surface guard passed.")
