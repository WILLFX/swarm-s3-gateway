#!/usr/bin/env python3
from pathlib import Path

manifest = Path("gateway/src/manifest.rs").read_text()

for token in [
    "owner catalog could not be decrypted; treating as empty",
    "owner_catalog_decrypt_failure_falls_back_to_empty_catalog",
]:
    if token in manifest:
        raise SystemExit(f"FAILED: unsafe owner catalog fallback token remains: {token}")

start = manifest.index("fn decode_owner_catalog_manifest_bytes")
end = manifest.index("pub async fn write_owner_catalog_manifest")
decode_fn = manifest[start:end]

if "RootCatalogManifest::default()" in decode_fn:
    raise SystemExit(
        "FAILED: decode_owner_catalog_manifest_bytes must not return an empty catalog on decrypt/decode failure"
    )

if "failed to decrypt owner catalog root" not in decode_fn:
    raise SystemExit("FAILED: owner catalog decrypt failure is not explicitly fail-closed")

print("Owner catalog fail-closed guard passed.")
