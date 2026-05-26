#!/usr/bin/env python3
from pathlib import Path

runtime = Path("trustless-proxy/src/runtime.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessRuntime",
    "LocalTrustlessRuntimePreparedResponse",
    "LocalTrustlessRuntimeCompletion",
    "LocalTrustlessRuntimePhase",
    "LocalTrustlessRuntimeError",
    "LocalTrustlessHandler::prepare_request",
    "LocalTrustlessHandler::complete_get_with_plaintext",
    "PreparedPendingResponse",
    "CompletedLocalResponse",
    "prepare_request",
    "complete_get_with_plaintext",
    "gateway_plaintext_access: false",
]

required_tests = [
    "runtime_prepares_put_as_pending_ciphertext_remote_response",
    "runtime_prepares_get_as_pending_local_decrypt_response",
    "runtime_completes_get_as_ready_local_plaintext_response",
    "runtime_prepares_delete_as_pending_ciphertext_remote_response",
    "runtime_prepares_list_without_object_key_id",
    "runtime_prepares_create_bucket_as_pending_anchor_response",
    "runtime_rejects_plaintext_body_outside_put_boundary",
    "runtime_rejects_completing_non_get_as_plaintext",
]

required_lib = [
    "pub mod runtime",
    "LocalTrustlessRuntime",
    "LocalTrustlessRuntimePreparedResponse",
]

required_workflow = [
    "Check trustless local proxy runtime surface",
    "./scripts/check_trustless_local_proxy_runtime_surface.py",
]

for token in required_source:
    if token not in runtime:
        raise SystemExit(f"FAILED: missing runtime token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in runtime:
        raise SystemExit(f"FAILED: forbidden runtime token: {forbidden}")

for token in required_tests:
    if token not in runtime:
        raise SystemExit(f"FAILED: missing runtime test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing runtime lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing runtime workflow token: {token}")

print("Trustless local proxy runtime surface guard passed.")
