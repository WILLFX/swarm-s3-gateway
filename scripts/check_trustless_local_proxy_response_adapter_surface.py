#!/usr/bin/env python3
from pathlib import Path

adapter = Path("trustless-proxy/src/response_adapter.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessResponseAdapter",
    "LocalTrustlessResponseEnvelope",
    "LocalTrustlessResponseState",
    "LocalTrustlessResponseAdapterError",
    "from_prepared_operation",
    "from_execution_result",
    "from_local_response",
    "PendingCiphertextOnlyRemoteRequest",
    "PendingLocalDecrypt",
    "PendingTrustlessBucketAnchor",
    "ReadyMetadataOnly",
    "ReadyLocalPlaintext",
    "gateway_plaintext_access: false",
]

required_tests = [
    "response_adapter_marks_put_preparation_as_pending_ciphertext_remote",
    "response_adapter_marks_get_preparation_as_pending_local_decrypt",
    "response_adapter_marks_create_bucket_preparation_as_pending_anchor",
    "response_adapter_builds_final_get_plaintext_response",
    "response_adapter_builds_final_metadata_response",
    "response_adapter_builds_delete_metadata_response_with_no_content_status",
    "response_adapter_rejects_gateway_plaintext_prepared_operation",
    "response_adapter_rejects_get_execution_without_plaintext_body",
]

required_lib = [
    "pub mod response_adapter",
    "LocalTrustlessResponseAdapter",
    "LocalTrustlessResponseEnvelope",
]

required_workflow = [
    "Check trustless local proxy response adapter surface",
    "./scripts/check_trustless_local_proxy_response_adapter_surface.py",
]

for token in required_source:
    if token not in adapter:
        raise SystemExit(f"FAILED: missing response adapter token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in adapter:
        raise SystemExit(f"FAILED: forbidden response adapter token: {forbidden}")

for token in required_tests:
    if token not in adapter:
        raise SystemExit(f"FAILED: missing response adapter test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing response adapter lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing response adapter workflow token: {token}")

print("Trustless local proxy response adapter surface guard passed.")
