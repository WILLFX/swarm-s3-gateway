#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

put_object = ROOT / "gateway/src/routes/put_object.rs"
trustless_endpoint = ROOT / "gateway/src/routes/trustless_ciphertext_gateway.rs"
workflow = ROOT / ".github/workflows/rust.yml"
docs = ROOT / "docs/private-lifecycle-operator-guide.md"

errors = []


def read(path: Path) -> str:
    if not path.exists():
        errors.append(f"missing required file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text()


def production(text: str) -> str:
    return text.split("#[cfg(test)]", 1)[0]


put_text = read(put_object)
trustless_text = read(trustless_endpoint)
workflow_text = read(workflow)
docs_text = read(docs)

production_routes = {
    "gateway/src/routes/put_object.rs": production(put_text),
    "gateway/src/routes/trustless_ciphertext_gateway.rs": production(trustless_text),
}

for label, text in production_routes.items():
    for forbidden in [
        "put_object_and_update_pointer",
        "get_pointer_bytes",
        "BeeClient::derive_topic",
        "ensure_feed_manifest",
        "publish_soc_pointer",
    ]:
        if forbidden in text:
            errors.append(f"{label} production route uses mutable Bee pointer API: {forbidden}")

for token in [
    "state.bee_client.put_bytes(body).await",
    "read_public_bucket_manifest_from_root(",
    "&chain_bucket.bucket_manifest_root",
    "submit_anchor_object(",
]:
    if token not in put_text:
        errors.append(f"public PUT missing canonical chain-root/raw-bytes token: {token}")

for token in [
    "put_bytes(Bytes::from(encrypted_manifest))",
    "validate_manifest_precondition(",
    "update_bucket_manifest_root_for_put_anchor(",
    "update_bucket_manifest_root_for_delete_anchor(",
]:
    if token not in trustless_text:
        errors.append(f"trustless ciphertext endpoint missing canonical raw-bytes/CAS token: {token}")

for forbidden in [
    "TRUSTLESS_MANIFEST_KEY",
    "storage_bucket",
]:
    if forbidden in production(trustless_text):
        errors.append(f"trustless ciphertext endpoint retains pointer-addressing token: {forbidden}")

for token in [
    "Canonical gateway writes do not publish mutable Bee pointers",
    "current chain-anchored roots",
]:
    if token not in docs_text:
        errors.append(f"operator guide missing canonical pointer policy token: {token}")

if "check_gateway_pointer_canonical_state_surface.py" not in workflow_text:
    errors.append("Rust workflow does not run pointer canonical-state surface guard")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print("Gateway pointer canonical-state surface guard passed.")
