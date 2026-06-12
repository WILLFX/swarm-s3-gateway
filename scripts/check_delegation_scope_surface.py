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
    "update_bucket_manifest_root_for_put_cas": "OP_PUT_OBJECT",
    "update_bucket_manifest_root_for_delete_cas": "OP_DELETE_OBJECT",
}

for fn_name, token in checks.items():
    body = fn_body(fn_name)
    if token not in body:
        fail(f"{fn_name} must use {token}")

for fn_name in [
    "grant_trustless_bucket_delegation",
    "revoke_trustless_bucket_delegation",
]:
    body = fn_body(fn_name)
    for token in [
        "BucketType::TrustlessPrivate",
        "expected_bucket_generation",
        "expected_bucket_state_epoch",
        "expected_encryption_version",
        "expected_bucket_manifest_root",
        "ensure_bucket_state_matches",
        "record.bucket_generation",
        "bump_bucket_state_epoch(&mut record)",
        "self.bucket_map.insert(bucket_name_hash, &record)",
    ]:
        if token not in body:
            fail(f"{fn_name} missing trustless bucket policy epoch token: {token}")

object_auth = fn_body("ensure_object_operation_authorized")
for token in [
    "let caller = Self::account_to_bytes(caller)",
    "caller == owner",
    "BucketType::TrustlessPrivate",
    "trustless_bucket_delegations",
    "record.bucket_generation",
    "evaluate_bucket_scoped_delegation",
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

bucket_scoped_eval_body = fn_body("evaluate_bucket_scoped_delegation")
for token in [
    "now > entry.expires_at",
    "Error::DelegationExpired",
    "(entry.allowed_operations & required_scope) != required_scope",
    "Error::InsufficientScope",
]:
    if token not in bucket_scoped_eval_body:
        fail(f"evaluate_bucket_scoped_delegation missing {token}")

trustless_branch_start = object_auth.find("BucketType::TrustlessPrivate")
fallback_start = object_auth.find("fetch_delegation")
if trustless_branch_start == -1 or fallback_start == -1 or trustless_branch_start > fallback_start:
    fail("trustless bucket delegation check must happen before owner-wide identity delegation fallback")

trustless_branch = object_auth[trustless_branch_start:fallback_start]
for token in ["fetch_delegation", "evaluate_delegation"]:
    if token in trustless_branch:
        fail(f"trustless bucket branch must not use owner-wide identity delegation token: {token}")

for forbidden in [
    "pub fn update_bucket_manifest_root_for_put(",
    "pub fn update_bucket_manifest_root_for_delete(",
]:
    if forbidden in bucket:
        fail(f"legacy non-CAS bucket mutation method still present: {forbidden}")

for token in [
    "trustless_private_root_update_requires_bucket_scoped_delegation_for_non_owner",
    "trustless_bucket_delegation_revoke_bumps_state_epoch",
    "Err(Error::StaleBucketStateEpoch)",
]:
    if token not in bucket:
        fail(f"bucket contract missing trustless bucket delegation regression test token: {token}")

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
