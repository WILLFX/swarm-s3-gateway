#!/usr/bin/env python3
from pathlib import Path
import re

bucket = Path("contracts/s3_bucket_contract/src/lib.rs").read_text()
common = Path("contracts/common/src/lib.rs").read_text()

def fail(message: str) -> None:
    raise SystemExit(f"FAILED: {message}")

def fn_body(name: str) -> str:
    pattern = rf"fn {name}\b.*?\n        }}\n"
    match = re.search(pattern, bucket, flags=re.S)
    if not match:
        fail(f"function not found: {name}")
    return match.group(0)

checks = {
    "ensure_create_authorized": "OP_CREATE_BUCKET",
    "ensure_delete_authorized": "OP_DELETE_BUCKET",
    "ensure_increment_authorized": "OP_PUT_OBJECT",
    "update_bucket_manifest_root_for_put": "OP_PUT_OBJECT",
    "update_bucket_manifest_root_for_delete": "OP_DELETE_OBJECT",
}

for fn_name, token in checks.items():
    body = fn_body(fn_name)
    if token not in body:
        fail(f"{fn_name} must use {token}")

object_auth = fn_body("ensure_object_operation_authorized")
for token in [
    "Self::account_to_bytes(caller) == owner",
    "fetch_delegation",
    "evaluate_delegation",
    "required_scope",
]:
    if token not in object_auth:
        fail(f"ensure_object_operation_authorized missing {token}")

eval_body = fn_body("evaluate_delegation")
for token in [
    "now > entry.expires_at",
    "Error::DelegationExpired",
    "(entry.allowed_operations & required_scope) != required_scope",
    "Error::InsufficientScope",
]:
    if token not in eval_body:
        fail(f"evaluate_delegation missing {token}")

for token in [
    "pub const OP_PUT_OBJECT",
    "pub const OP_GET_OBJECT",
    "pub const OP_DELETE_OBJECT",
    "pub const OP_LIST_OBJECTS",
    "pub const OP_HEAD_OBJECT",
    "pub const OP_CREATE_BUCKET",
    "pub const OP_DELETE_BUCKET",
    "pub const OP_ALL: u32 = 0b01111111",
]:
    if token not in common:
        fail(f"common operation constants missing or changed: {token}")

print("Delegation scope surface guard passed.")
