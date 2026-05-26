#!/usr/bin/env python3
from pathlib import Path

service = Path("trustless-proxy/src/service.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessLocalService",
    "TrustlessLocalServicePreparedOperation",
    "TrustlessLocalServiceNextAction",
    "TrustlessLocalServiceError",
    "TrustlessPipelineInput",
    "TrustlessLocalPipeline::plan",
    "TrustlessExecutionCoordinator",
    "TrustlessExecutionBoundaryRequirements",
    "SendCiphertextOnlyRemoteRequest",
    "AwaitCiphertextThenDecryptLocally",
    "CreateTrustlessBucketAnchor",
    "expected_local_response",
    "gateway_plaintext_access: false",
]

required_tests = [
    "service_prepares_put_for_ciphertext_only_remote_request",
    "service_prepares_get_awaiting_ciphertext_and_local_decrypt",
    "service_completes_get_with_local_plaintext_response",
    "service_prepares_head_list_and_delete_as_metadata_remote_operations",
    "service_prepares_create_bucket_anchor_without_remote_gateway",
    "service_rejects_plaintext_outside_put_boundary",
    "service_rejects_completing_non_get_as_plaintext_response",
]

required_lib = [
    "pub mod service",
    "TrustlessLocalService",
    "TrustlessLocalServicePreparedOperation",
]

required_workflow = [
    "Check trustless local proxy service surface",
    "./scripts/check_trustless_local_proxy_service_surface.py",
]

for token in required_source:
    if token not in service:
        raise SystemExit(f"FAILED: missing trustless local service token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in service:
        raise SystemExit(f"FAILED: forbidden trustless local service token: {forbidden}")

for token in required_tests:
    if token not in service:
        raise SystemExit(f"FAILED: missing trustless local service test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless local service lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless local service workflow token: {token}")

print("Trustless local proxy service surface guard passed.")
