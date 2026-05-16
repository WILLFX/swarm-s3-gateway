# Swarm S3 Gateway

Swarm S3 Gateway is an S3-compatible gateway backed by Swarm storage and on-chain contract anchors.

The gateway supports public and private bucket/object flows. Public objects can expose their Swarm storage reference for transparency. Private objects are encrypted and private S3 responses hide Swarm references so clients do not receive storage/decryption references through normal S3-compatible headers or listings.

## Current status

The project currently has:

- Public bucket/object lifecycle support
- Private bucket/object lifecycle support
- End-to-end private lifecycle smoke testing
- Contract-backed identity registration
- Contract-backed bucket anchoring
- Private object encryption and manifest handling
- CI guards against silent development signer fallbacks
- CI guards for unsafe secret examples in docs
- CI guards for local and production environment templates
- Separate local and production environment examples

## Private bucket security model

Swarm data is publicly retrievable if someone has the correct reference. For private objects, the gateway encrypts object data and must avoid leaking usable Swarm references through private S3 responses.

For private buckets and private objects, the gateway omits:

    x-amz-meta-swarm-ref

from:

- PUT object responses
- HEAD object responses
- GET object responses
- ListObjectsV2 responses

Public buckets may keep this header because public objects are intended to be externally readable or verifiable.

## Environment templates

Use the local template only for development:

    .env.local.example

Use the production template for deployment planning:

    .env.production.example

Production deployments must replace all placeholder values with real operator-controlled secrets.

Do not use development signers, weak placeholder keys, or development fallback flags in production.

## Local development

Copy the local example and fill in required values:

    cp .env.local.example .env.local

Then export the values into your shell before running the gateway.

The gateway expects a running chain node and a reachable Bee API.

## Production configuration

Production deployments should use:

    .env.production.example

Production requires real values for:

- S3GW_MASTER_SERVICE_KEY_HEX
- S3GW_BEE_STAMP_BATCH_ID
- S3GW_BEE_FEED_SECRET_KEY_HEX
- S3GW_ANCHOR_SIGNER_SURI
- S3GW_SUDO_SIGNER_SURI
- S3GW_IDENTITY_REGISTRAR_SIGNER_SURI
- S3GW_BUCKET_OWNER_SIGNER_SURI

Generate the Bee feed signing secret with:

    openssl rand -hex 32

Do not enable development fallback flags in production.

## Run the gateway

Example local run:

    RUST_LOG=gateway=debug cargo run -p gateway --bin gateway

## Private lifecycle smoke test

After the gateway is running, run:

    ./scripts/private_lifecycle_smoke.sh

The expected result is:

    PRIVATE LIFECYCLE SMOKE PASSED

This verifies the private bucket lifecycle:

- Register identity
- Create private bucket
- PUT private object
- HEAD private object
- GET private object
- LIST private bucket
- DELETE private object
- Confirm object is gone
- DELETE private bucket

## Local checks

Run the main local checks:

    ./scripts/check_env_templates.py
    ./scripts/check_docs_secret_safety.py
    ./scripts/check_no_silent_dev_signers.sh
    cargo check -p gateway

Private response header behavior can be checked with:

    cargo test -p gateway private_put_encrypts_payload_writes_manifests_anchors_and_hides_swarm_ref -- --nocapture
    cargo test -p gateway private_get_decrypts_payload_and_omits_swarm_ref_header -- --nocapture
    cargo test -p gateway private_head_reads_metadata_but_not_payload_and_omits_swarm_ref_header -- --nocapture
    cargo test -p gateway private_list_reads_bucket_manifest_only_and_omits_swarm_ref_header -- --nocapture

## Detailed operator guide

See:

    docs/private-lifecycle-operator-guide.md

That guide contains the deeper private lifecycle and operator setup details.

## Security notes

The gateway has been hardened to avoid silent production use of development signers and development fallbacks.

Current safeguards include:

- Required production signer environment variables
- Explicit gating of development defaults
- Explicit gating of Bee development fallback behavior
- Required production Bee feed secret
- CI guard for unsafe signer regressions
- CI guard for unsafe secret examples in docs
- CI guard for environment template completeness

## Remaining security work

The next major security work should focus on delegation and authorization scope tests:

- Contract-level delegation scope tests
- Gateway delegation end-to-end tests
- Negative permission tests
- Revocation behavior tests
- Encryption version rotation design

These are the next layers needed to prove that unauthorized accounts cannot access or mutate private bucket state.
