#!/usr/bin/env python3
from pathlib import Path

DOCS = [Path("docs/private-lifecycle-operator-guide.md")]

DANGEROUS_VALUES = [
    "//Alice",
    "dev-gas-tank-seed",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "S3GW_ENABLE_DEV_DEFAULTS=true",
    "S3GW_BEE_ALLOW_DEV_BYTES_FALLBACK=true",
]

SAFETY_WORDS = [
    "local-development",
    "local development",
    "must never be used in production",
    "do not enable",
    "do not use",
    "only for local",
    "placeholder",
]

failed = False

for path in DOCS:
    text = path.read_text()
    lines = text.splitlines()

    for index, line in enumerate(lines):
        for value in DANGEROUS_VALUES:
            if value not in line:
                continue

            start = max(0, index - 6)
            end = min(len(lines), index + 7)
            context = "\n".join(lines[start:end]).lower()

            if not any(word in context for word in SAFETY_WORDS):
                print(
                    f"FAILED: {path}:{index + 1} contains {value!r} "
                    "without nearby production-safety wording"
                )
                failed = True

if failed:
    raise SystemExit(1)

print("Docs secret safety guard passed.")
