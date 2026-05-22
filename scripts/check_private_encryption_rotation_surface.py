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

print("Private encryption rotation surface guard passed.")
