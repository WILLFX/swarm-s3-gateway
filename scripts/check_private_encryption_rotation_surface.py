#!/usr/bin/env python3
from pathlib import Path

def fail(msg: str) -> None:
    raise SystemExit(f"FAILED: {msg}")

doc = Path("docs/security/private-encryption-version-rotation.md")
if not doc.exists():
    fail("missing docs/security/private-encryption-version-rotation.md")

text = doc.read_text()

required_doc_phrases = [
    "simply incrementing the on-chain bucket `encryption_version` is not enough",
    "migrate/re-encrypt the bucket manifest under the new version",
    "store the bucket manifest's encryption version alongside the bucket manifest root",
    "does not yet provide a production-safe bucket encryption rotation workflow",
    "Do not expose `increment_encryption_version` as an operator/user rotation feature",
    "The gateway operator signing helper must not sign increment operations",
    "The bucket contract rejects `increment_encryption_version` once `bucket_manifest_root` is non-empty",
    "not a full rotation workflow",
]

for phrase in required_doc_phrases:
    if phrase not in text:
        fail(f"rotation doc missing required phrase: {phrase}")

private_read = Path("gateway/src/routes/private_object_read.rs").read_text()
for token in [
    "entry.encryption_version",
    "private_entry_lookup_uses_entry_encryption_version",
    "object_record.manifest.encryption_version != entry.encryption_version",
]:
    if token not in private_read:
        fail(f"private object read path missing guard token: {token}")

put_object = Path("gateway/src/routes/put_object.rs").read_text()
for token in [
    "let encryption_version = chain_bucket.encryption_version;",
    "PrivateBucketObjectEntry",
    "encryption_version,",
]:
    if token not in put_object:
        fail(f"private PUT path missing version token: {token}")

bucket_contract = Path("contracts/s3_bucket_contract/src/lib.rs").read_text()
for token in [
    "BucketManifestRootNotEmpty",
    "if !record.bucket_manifest_root.is_empty()",
    "return Err(Error::BucketManifestRootNotEmpty)",
    "increment_rejects_non_empty_bucket_manifest_root",
]:
    if token not in bucket_contract:
        fail(f"bucket contract missing unsafe rotation guard token: {token}")

signer = Path("gateway/src/bin/sign_bucket_op.rs").read_text()
for forbidden in [
    "s3gw/v1/increment_encryption_version",
    "create|create-trustless|delete|increment",
    "use create, create-trustless, delete, or increment",
]:
    if forbidden in signer:
        fail(f"sign_bucket_op still exposes unsafe increment signing token: {forbidden}")

contracts_abi = Path("gateway/src/contracts_abi.rs").read_text()
for forbidden in [
    "BUCKET_INCREMENT_ENCRYPTION_VERSION_SELECTOR",
    "encode_bucket_increment_encryption_version",
]:
    if forbidden in contracts_abi:
        fail(f"gateway contract ABI still exposes unsafe increment helper: {forbidden}")

registry = Path("gateway/src/chain/registry.rs").read_text()
for forbidden in [
    "submit_increment_encryption_version",
    "failed to submit increment_encryption_version extrinsic",
]:
    if forbidden in registry:
        fail(f"gateway chain client still exposes unsafe increment submit helper: {forbidden}")

workflow = Path(".github/workflows/rust.yml").read_text()
if "check_private_encryption_rotation_surface.py" not in workflow:
    fail("rust workflow does not run check_private_encryption_rotation_surface.py")

print("Private encryption rotation surface guard passed.")
