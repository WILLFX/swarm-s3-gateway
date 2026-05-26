#!/usr/bin/env python3
from pathlib import Path

coordinator = Path("trustless-proxy/src/execution_coordinator.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessExecutionCoordinator",
    "TrustlessExecutionResult",
    "TrustlessExecutionBoundaryRequirements",
    "TrustlessExecutionCoordinatorError",
    "TrustlessPipelinePlan",
    "CiphertextGatewayResponse",
    "LocalS3Response",
    "TrustlessOperationAssembler",
    "TrustlessRemoteGatewayExecutor",
    "coordinate_metadata_response",
    "coordinate_get_plaintext_response",
    "validate_remote_gateway_response",
    "operation_assembly_required",
    "remote_gateway_required",
    "gateway_plaintext_access: false",
]

required_tests = [
    "coordinator_returns_metadata_for_put_after_ciphertext_remote_stage",
    "coordinator_returns_local_plaintext_for_get_after_decrypt_stage",
    "coordinator_returns_metadata_for_head_list_delete_and_create",
    "coordinator_validates_ciphertext_only_remote_gateway_response",
    "coordinator_rejects_gateway_plaintext_remote_response",
    "coordinator_rejects_remote_action_mismatch",
    "coordinator_rejects_metadata_response_for_get_without_plaintext",
    "coordinator_rejects_plaintext_response_for_non_get_operation",
    "coordinator_handles_create_bucket_without_remote_gateway",
]

required_lib = [
    "pub mod execution_coordinator",
    "TrustlessExecutionCoordinator",
    "TrustlessExecutionCoordinatorError",
]

required_workflow = [
    "Check trustless local proxy execution coordinator surface",
    "./scripts/check_trustless_local_proxy_execution_coordinator_surface.py",
]

for token in required_source:
    if token not in coordinator:
        raise SystemExit(f"FAILED: missing execution coordinator token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in coordinator:
        raise SystemExit(f"FAILED: forbidden execution coordinator token: {forbidden}")

for token in required_tests:
    if token not in coordinator:
        raise SystemExit(f"FAILED: missing execution coordinator test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing execution coordinator lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing execution coordinator workflow token: {token}")

print("Trustless local proxy execution coordinator surface guard passed.")
