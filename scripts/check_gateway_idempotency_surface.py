#!/usr/bin/env python3
from pathlib import Path

root = Path(".")


def read(path: str) -> str:
    return (root / path).read_text()


idempotency = read("gateway/src/idempotency.rs")
put_object = read("gateway/src/routes/put_object.rs")
delete_object = read("gateway/src/routes/delete_object.rs")
create_bucket = read("gateway/src/routes/create_bucket.rs")
delete_bucket = read("gateway/src/routes/delete_bucket.rs")
trustless = read("gateway/src/routes/trustless_ciphertext_gateway.rs")
docs = read("docs/security/gateway-idempotency.md")
trustless_docs = read("docs/security/trustless-private-access-model.md")
workflow = read(".github/workflows/rust.yml")

required = {
    "idempotency header": (idempotency, "x-s3gw-idempotency-key"),
    "journal env": (idempotency, "S3GW_IDEMPOTENCY_JOURNAL_PATH"),
    "started journal event": (idempotency, "Started"),
    "succeeded journal event": (idempotency, "Succeeded"),
    "failed journal event": (idempotency, "Failed"),
    "store not configured fail closed": (idempotency, "StoreNotConfigured"),
    "store unavailable fail closed": (idempotency, "StoreUnavailable"),
    "in-progress conflict": (idempotency, "InProgress"),
    "digest conflict": (idempotency, "Conflict"),
    "typed digest": (idempotency, "request_digest_hex"),
    "stored success persistence": (idempotency, "persist_stored_success"),
    "public/private put reservation": (put_object, "begin_object_put_idempotency"),
    "public put replay header": (put_object, "stored_header_response"),
    "private put omits replay swarm ref": (put_object, "stored_empty_response(StatusCode::OK)"),
    "delete object reservation": (delete_object, "begin_object_delete_idempotency"),
    "delete object no-content replay": (
        delete_object,
        "stored_empty_response(StatusCode::NO_CONTENT)",
    ),
    "create bucket reservation": (create_bucket, "begin_create_bucket_idempotency"),
    "trustless create no location journal": (
        create_bucket,
        "CreateBucketMode::TrustlessPrivate => stored_empty_response(StatusCode::OK)",
    ),
    "delete bucket reservation": (delete_bucket, "begin_delete_bucket_idempotency"),
    "delete bucket no-content replay": (
        delete_bucket,
        "stored_empty_response(StatusCode::NO_CONTENT)",
    ),
    "trustless mutation idempotency": (trustless, "requires_idempotency"),
    "trustless digest": (trustless, "ciphertext_gateway_idempotency_digest"),
    "trustless json replay": (trustless, "persist_json_success"),
    "docs header": (docs, "x-s3gw-idempotency-key"),
    "docs journal env": (docs, "S3GW_IDEMPOTENCY_JOURNAL_PATH"),
    "docs gateway-local": (docs, "gateway-local idempotency"),
    "docs no global claim": (docs, "does not provide global multi-gateway idempotency"),
    "docs canonical future": (docs, "canonical operation receipts"),
    "trustless docs link": (trustless_docs, "docs/security/gateway-idempotency.md"),
    "workflow guard": (workflow, "check_gateway_idempotency_surface.py"),
}

for label, (content, token) in required.items():
    if token not in content:
        raise SystemExit(f"FAILED: missing {label}: {token}")

for forbidden in [
    "global multi-gateway idempotency is complete",
    "provides global multi-gateway idempotency",
    "chain-anchored operation receipts are implemented",
]:
    if forbidden in docs:
        raise SystemExit(f"FAILED: idempotency docs overclaim: {forbidden}")

print("Gateway idempotency surface guard passed.")
