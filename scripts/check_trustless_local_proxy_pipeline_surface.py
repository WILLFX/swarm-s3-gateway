#!/usr/bin/env python3
from pathlib import Path

pipeline = Path("trustless-proxy/src/pipeline.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessLocalPipeline",
    "TrustlessPipelineInput",
    "TrustlessPipelinePlan",
    "TrustlessPipelineError",
    "TrustlessLocalOperationRouter",
    "TrustlessRequestContextBuilder",
    "LocalS3Request",
    "TrustlessRequestContextInput",
    "plaintext_body_available_locally",
    "remote_gateway_required",
    "gateway_plaintext_access: false",
]

required_tests = [
    "pipeline_plans_put_from_local_plaintext_to_ciphertext_gateway_stages",
    "pipeline_plans_get_with_local_decrypt_and_plaintext_return_stage",
    "pipeline_plans_head_as_metadata_only",
    "pipeline_plans_list_without_object_key_id",
    "pipeline_plans_delete_with_local_manifest_mutation",
    "pipeline_plans_create_bucket_without_remote_gateway",
    "pipeline_rejects_plaintext_outside_put_boundary",
    "pipeline_rejects_missing_context_identity_fields",
]

required_lib = [
    "pub mod pipeline",
    "TrustlessLocalPipeline",
    "TrustlessPipelineInput",
]

required_workflow = [
    "Check trustless local proxy pipeline surface",
    "./scripts/check_trustless_local_proxy_pipeline_surface.py",
]

for token in required_source:
    if token not in pipeline:
        raise SystemExit(f"FAILED: missing trustless pipeline token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in pipeline:
        raise SystemExit(f"FAILED: forbidden trustless pipeline token: {forbidden}")

for token in required_tests:
    if token not in pipeline:
        raise SystemExit(f"FAILED: missing trustless pipeline test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless pipeline lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless pipeline workflow token: {token}")

print("Trustless local proxy pipeline surface guard passed.")
