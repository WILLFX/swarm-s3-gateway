#!/usr/bin/env python3
from pathlib import Path

sigv4 = Path("gateway/src/auth/sigv4.rs").read_text()
identity = Path("gateway/tests/identity_handshake.rs").read_text()

required = [
    "SIGV4_MAX_CLOCK_SKEW_SECONDS",
    "ensure_amz_date_fresh(amz_date, OffsetDateTime::now_utc().unix_timestamp())",
    "fn parse_amz_date_epoch_seconds",
    "x-amz-date outside allowed clock skew",
    "sigv4_freshness_rejects_stale_and_future_requests",
]

for token in required:
    if token not in sigv4:
        raise SystemExit(f"FAILED: missing SigV4 freshness token: {token}")

validate_start = sigv4.index("pub async fn validate")
validate_end = sigv4.index("let access_key_hash = hash_access_key_id", validate_start)
validate_prefix = sigv4[validate_start:validate_end]

if "ensure_amz_date_fresh" not in validate_prefix:
    raise SystemExit("FAILED: SigV4 freshness must be checked before chain credential lookup")

if '"20250101T120000Z"' in identity:
    raise SystemExit("FAILED: identity handshake tests still use stale fixed x-amz-date")

if "format_amz_date(OffsetDateTime::now_utc())" not in identity:
    raise SystemExit("FAILED: identity handshake tests must sign with a fresh x-amz-date")

print("SigV4 freshness surface guard passed.")
