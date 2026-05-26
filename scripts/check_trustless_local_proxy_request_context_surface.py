#!/usr/bin/env python3
from pathlib import Path

context = Path("trustless-proxy/src/request_context.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "TrustlessRequestContextInput",
    "TrustlessRequestContext",
    "TrustlessRequestContextBuilder",
    "TrustlessRequestContextError",
    "TrustlessPreflightRequest",
    "LocalS3RouteIntent",
    "plaintext_body_allowed_locally",
    "gateway_plaintext_access: false",
    "normalize_recipients",
    "MissingObjectKeyId",
    "UnexpectedPlaintextBody",
]

required_tests = [
    "put_context_preserves_plaintext_only_at_local_boundary",
    "get_head_delete_contexts_require_object_key_id_without_plaintext",
    "list_and_create_contexts_do_not_require_object_key_id",
    "context_builder_rejects_missing_required_identity_fields",
    "context_builder_rejects_missing_object_key_id_for_object_operations",
    "context_builder_rejects_missing_recipients",
    "context_builder_rejects_plaintext_outside_put_boundary",
    "context_builder_accepts_real_local_s3_put_intent",
]

required_lib = [
    "pub mod request_context",
    "TrustlessRequestContextBuilder",
    "TrustlessRequestContextInput",
]

required_workflow = [
    "Check trustless local proxy request context surface",
    "./scripts/check_trustless_local_proxy_request_context_surface.py",
]

for token in required_source:
    if token not in context:
        raise SystemExit(f"FAILED: missing trustless request context token: {token}")

for forbidden in [
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in context:
        raise SystemExit(f"FAILED: forbidden trustless request context token: {forbidden}")

for token in required_tests:
    if token not in context:
        raise SystemExit(f"FAILED: missing trustless request context test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing trustless request context lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing trustless request context workflow token: {token}")

print("Trustless local proxy request context surface guard passed.")
