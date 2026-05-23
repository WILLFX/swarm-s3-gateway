#!/usr/bin/env python3
from pathlib import Path

def fail(msg: str) -> None:
    raise SystemExit(f"FAILED: {msg}")

main = Path("gateway/src/main.rs").read_text()
lib = Path("gateway/src/lib.rs").read_text()
limits = Path("gateway/src/request_limits.rs").read_text()
local_env = Path(".env.local.example").read_text()
prod_env = Path(".env.production.example").read_text()

required = [
    (lib, "pub mod request_limits;"),
    (limits, "S3GW_MAX_REQUEST_BODY_BYTES"),
    (limits, "DEFAULT_MAX_REQUEST_BODY_BYTES"),
    (limits, "max_request_body_bytes_from_env"),
    (limits, "must be greater than zero"),
    (main, "DefaultBodyLimit::max(max_request_body_bytes)"),
    (main, "max_request_body_bytes_from_env()?"),
    (local_env, "S3GW_MAX_REQUEST_BODY_BYTES=67108864"),
    (prod_env, "S3GW_MAX_REQUEST_BODY_BYTES=67108864"),
]

for text, token in required:
    if token not in text:
        fail(f"missing request body limit token: {token}")

if "body: Bytes" not in Path("gateway/src/routes/put_object.rs").read_text():
    fail("PUT route no longer exposes buffered Bytes; revisit body limit guard")

print("Request body limit surface guard passed.")
