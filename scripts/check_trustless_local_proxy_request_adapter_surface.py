#!/usr/bin/env python3
from pathlib import Path

adapter = Path("trustless-proxy/src/request_adapter.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessRequestAdapter",
    "LocalTrustlessRequestInput",
    "LocalTrustlessRequestPreparation",
    "LocalTrustlessRequestAdapterError",
    "LocalS3Request",
    "TrustlessPipelineInput",
    "TrustlessLocalService::prepare",
    "build_s3_request",
    "build_pipeline_input",
    "plaintext_body_allowed_locally",
    "gateway_plaintext_access: false",
]

required_tests = [
    "adapter_builds_put_pipeline_input_with_local_plaintext_only",
    "adapter_builds_get_pipeline_input_awaiting_local_decrypt",
    "adapter_builds_head_delete_as_ciphertext_remote_metadata_operations",
    "adapter_builds_list_pipeline_input_without_object_key_id",
    "adapter_builds_create_bucket_anchor_without_remote_gateway",
    "adapter_rejects_get_with_plaintext_body",
    "adapter_rejects_missing_bucket_identity_context",
]

required_lib = [
    "pub mod request_adapter",
    "LocalTrustlessRequestAdapter",
    "LocalTrustlessRequestInput",
]

required_workflow = [
    "Check trustless local proxy request adapter surface",
    "./scripts/check_trustless_local_proxy_request_adapter_surface.py",
]

for token in required_source:
    if token not in adapter:
        raise SystemExit(f"FAILED: missing request adapter token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in adapter:
        raise SystemExit(f"FAILED: forbidden request adapter token: {forbidden}")

for token in required_tests:
    if token not in adapter:
        raise SystemExit(f"FAILED: missing request adapter test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing request adapter lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing request adapter workflow token: {token}")

print("Trustless local proxy request adapter surface guard passed.")
