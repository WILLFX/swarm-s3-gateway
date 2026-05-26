#!/usr/bin/env python3
from pathlib import Path

mapping = Path("trustless-proxy/src/http_mapping.rs").read_text()
lib = Path("trustless-proxy/src/lib.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()

required_source = [
    "LocalTrustlessHttpMapper",
    "LocalTrustlessHttpRequest",
    "LocalTrustlessHttpRequestContext",
    "LocalTrustlessHttpResponse",
    "LocalTrustlessHttpMappingError",
    "LocalTrustlessHttpMethod",
    "LocalTrustlessRequestInput",
    "LocalTrustlessResponseEnvelope",
    "request_to_local_input",
    "response_from_envelope",
    "x-s3w-gateway-plaintext-access",
    "gateway_plaintext_access: false",
]

required_tests = [
    "http_mapper_maps_put_object_to_local_trustless_input",
    "http_mapper_maps_get_head_and_delete_object_inputs",
    "http_mapper_maps_list_objects_v2_without_object_key_id",
    "http_mapper_maps_trustless_bucket_create_without_remote_object_key",
    "http_mapper_rejects_plaintext_body_outside_put_object",
    "http_mapper_rejects_missing_object_key_for_object_operation",
    "http_mapper_rejects_unsupported_post_method",
    "http_mapper_maps_response_envelope_to_http_response",
    "http_mapper_maps_local_plaintext_get_envelope_to_http_body",
    "http_mapper_rejects_gateway_plaintext_response_envelope",
]

required_lib = [
    "pub mod http_mapping",
    "LocalTrustlessHttpMapper",
    "LocalTrustlessHttpRequest",
]

required_workflow = [
    "Check trustless local proxy HTTP mapping surface",
    "./scripts/check_trustless_local_proxy_http_mapping_surface.py",
]

for token in required_source:
    if token not in mapping:
        raise SystemExit(f"FAILED: missing HTTP mapping token: {token}")

for forbidden in [
    "TcpListener",
    "axum::",
    "hyper::",
    "send_plaintext_to_gateway",
    "gateway_plaintext_payload",
    "remote_plaintext_body",
]:
    if forbidden in mapping:
        raise SystemExit(f"FAILED: forbidden HTTP mapping token: {forbidden}")

for token in required_tests:
    if token not in mapping:
        raise SystemExit(f"FAILED: missing HTTP mapping test token: {token}")

for token in required_lib:
    if token not in lib:
        raise SystemExit(f"FAILED: missing HTTP mapping lib token: {token}")

for token in required_workflow:
    if token not in workflow:
        raise SystemExit(f"FAILED: missing HTTP mapping workflow token: {token}")

print("Trustless local proxy HTTP mapping surface guard passed.")
