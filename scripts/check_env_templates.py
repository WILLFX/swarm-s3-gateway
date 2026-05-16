#!/usr/bin/env python3
from pathlib import Path

LOCAL = Path(".env.local.example")
PROD = Path(".env.production.example")

required_common = [
    "S3GW_CHAIN_RPC_URL=",
    "S3GW_BEE_API_URL=",
    "S3GW_BIND_ADDR=",
    "S3GW_EXPECTED_REGION=",
    "S3GW_EXPECTED_SERVICE=",
    "S3GW_ALLOW_UNSIGNED_PAYLOAD=",
    "S3GW_MASTER_SERVICE_KEY_HEX=",
    "S3GW_BEE_STAMP_BATCH_ID=",
    "S3GW_BEE_FEED_SECRET_KEY_HEX=",
    "S3GW_ANCHOR_SIGNER_SURI=",
    "S3GW_SUDO_SIGNER_SURI=",
    "S3GW_IDENTITY_REGISTRAR_SIGNER_SURI=",
    "S3GW_BUCKET_OWNER_SIGNER_SURI=",
]

def fail(msg: str) -> None:
    raise SystemExit(f"FAILED: {msg}")

for path in [LOCAL, PROD]:
    if not path.exists():
        fail(f"{path} is missing")
    text = path.read_text()
    if len(text.strip()) < 200:
        fail(f"{path} is empty or too small")
    for key in required_common:
        if key not in text:
            fail(f"{path} missing {key}")

local_text = LOCAL.read_text()
for required in [
    "//Alice",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "S3GW_ENABLE_DEV_DEFAULTS=true",
    "S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK=true",
    "Local development only",
]:
    if required not in local_text:
        fail(f"{LOCAL} missing local-development marker/value {required!r}")

prod_text = PROD.read_text()
prod_uncommented = [
    line.strip()
    for line in prod_text.splitlines()
    if line.strip() and not line.strip().startswith("#")
]

for bad in [
    "//Alice",
    "dev-gas-tank-seed",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "S3GW_ENABLE_DEV_DEFAULTS=true",
    "S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK=true",
]:
    if any(bad in line for line in prod_uncommented):
        fail(f"{PROD} contains unsafe production value {bad!r}")

print("Env template guard passed.")
