#!/usr/bin/env python3
from pathlib import Path

gateway_list = Path("gateway/src/routes/list_objects_v2.rs").read_text()
trustless_engine = Path("trustless-proxy/src/execution_engine.rs").read_text()
workflow = Path(".github/workflows/rust.yml").read_text()


def require(label: str, text: str, tokens: list[str]) -> None:
    for token in tokens:
        if token not in text:
            raise SystemExit(f"FAILED: {label} missing token: {token}")


require(
    "gateway ListObjectsV2 snapshot pagination",
    gateway_list,
    [
        "LIST_CONTINUATION_TOKEN_PREFIX",
        "HmacSha256",
        "resolve_list_snapshot",
        "encode_list_continuation_token",
        "decode_list_continuation_token",
        "sign_list_token_payload",
        "bucket_id_hex",
        "manifest_root_hex",
        "creation_date",
        "token signature is invalid",
        "signed token should resolve its original snapshot even after root advances",
        "list_continuation_token_rejects_signature_tampering",
    ],
)

require(
    "trustless local ListObjectsV2 snapshot pagination",
    trustless_engine,
    [
        "LOCAL_LIST_CONTINUATION_TOKEN_PREFIX",
        "resolve_local_list_snapshot",
        "encode_local_list_continuation_token",
        "decode_local_list_continuation_token",
        "trustless_list_objects_v2_response_body",
        "completed_list_http_response",
        "encrypted manifest changed since the continuation token was issued",
        "LIST should return XML body",
        "local_list_continuation_token_detects_manifest_drift",
    ],
)

require(
    "trustless PUT retry-churn guard",
    trustless_engine,
    [
        ".find(|entry| entry.object_key == object_key)",
        "unwrap_or_else(fresh_object_context_id_hex)",
        "sha256_hex(&plaintext)",
    ],
)

require(
    "workflow",
    workflow,
    [
        "Check list snapshot pagination surface",
        "./scripts/check_list_snapshot_pagination_surface.py",
        "Install trustless proxy native build dependencies",
        "cargo check -p trustless-proxy",
        "cargo test -p trustless-proxy -- --nocapture",
    ],
)

print("List snapshot pagination surface guard passed.")
