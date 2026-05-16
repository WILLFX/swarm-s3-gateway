# Swarm S3 Gateway

Swarm S3 Gateway is an S3-compatible gateway that stores object data on Swarm while using on-chain contracts to anchor identity and bucket state.

The goal is to make Swarm usable through familiar S3-style operations while supporting both public and private bucket flows.

This project is not only a storage proxy. It has three major parts working together:

1. **Gateway service**
2. **On-chain contracts**
3. **Swarm/Bee storage**

Each part has a different responsibility.

## Core architecture

### 1. Gateway service

The gateway is the S3-compatible HTTP service.

It is responsible for:

- Accepting S3-style requests such as PUT, GET, HEAD, LIST, and DELETE
- Validating request authentication
- Resolving identities from registered access keys
- Encrypting private object payloads before writing them to Swarm
- Decrypting private object payloads when an authorized client reads them
- Creating and reading object/bucket manifests
- Writing object bytes and manifest bytes to Bee/Swarm
- Calling the chain/contracts to anchor bucket and object manifest roots
- Hiding private Swarm references from private S3 responses

The gateway is the coordination layer. It speaks S3 to clients, Bee HTTP to Swarm, and contract calls to the chain.

### 2. On-chain contracts

The contracts are the source of truth for identity and bucket state.

The current contract-backed flows include:

- Identity registration
- Access key to owner mapping
- Bucket contract address configuration
- Identity contract address configuration
- Bucket manifest root anchoring
- Owner catalog root anchoring

The contracts are important because the gateway should not be the only place that remembers ownership and bucket state. The chain gives the system an auditable state anchor.

Future delegation and authorization tests should focus here first, because the contracts must prove that unauthorized accounts cannot mutate or access private bucket state.

### 3. Swarm/Bee storage

Swarm/Bee is the content-addressed storage backend.

It stores:

- Object payload bytes
- Encrypted private object bytes
- Object manifests
- Bucket manifests
- Catalog manifests

Swarm itself does not enforce privacy. If someone has a usable Swarm reference, they can try to fetch the bytes. For private objects, privacy depends on:

- Encrypting object payloads
- Keeping private manifest structure controlled by the gateway/contracts
- Not leaking usable Swarm references in private S3 responses
- Enforcing identity, ownership, and future delegation rules through the gateway and contracts

This means the gateway must treat Swarm references as sensitive for private objects.

## Public vs private buckets

### Public buckets

Public buckets are intended to be externally readable or verifiable.

For public objects, responses may expose:

    x-amz-meta-swarm-ref

This is useful because the Swarm reference lets users verify or fetch public content directly.

### Private buckets

Private buckets are different.

For private objects, exposing the Swarm reference can leak a storage/decryption path. Even if the payload is encrypted, the reference itself can reveal where the encrypted data lives and may allow direct retrieval attempts outside the gateway.

For that reason, private responses omit:

    x-amz-meta-swarm-ref

from:

- PUT object responses
- HEAD object responses
- GET object responses
- ListObjectsV2 responses

The gateway still stores and uses the Swarm references internally. It simply does not expose them through normal private S3-compatible responses.

## Private object flow

A private PUT flow works like this:

1. Client sends an S3 PUT request to the gateway.
2. Gateway validates the request identity.
3. Gateway encrypts the object payload.
4. Gateway writes the encrypted bytes to Bee/Swarm.
5. Gateway writes object and bucket manifests.
6. Gateway anchors the updated manifest root through the bucket contract.
7. Gateway returns an S3-compatible response without leaking `x-amz-meta-swarm-ref`.

A private GET flow works like this:

1. Client sends an S3 GET request to the gateway.
2. Gateway validates the request identity.
3. Gateway resolves the private object manifest.
4. Gateway fetches encrypted bytes from Bee/Swarm.
5. Gateway decrypts the payload.
6. Gateway returns the plaintext object body without leaking `x-amz-meta-swarm-ref`.

## Current status

The project currently has:

- Public bucket/object lifecycle support
- Private bucket/object lifecycle support
- End-to-end private lifecycle smoke testing
- Contract-backed identity registration
- Contract-backed bucket anchoring
- Private object encryption and manifest handling
- Private response Swarm reference hiding
- CI guards against silent development signer fallbacks
- CI guards for unsafe secret examples in docs
- CI guards for local and production environment templates
- Separate local and production environment examples

## Environment templates

Local development:

    .env.local.example

Production planning:

    .env.production.example

Production deployments must replace all placeholder values with real operator-controlled secrets.

Do not use development signers, weak placeholder keys, or development fallback flags in production.

## Run the gateway

Example local run:

    RUST_LOG=gateway=debug cargo run -p gateway --bin gateway

The gateway expects:

- A running chain node
- A reachable Bee API
- Required environment variables exported into the shell

## Private lifecycle smoke test

After the gateway is running, run:

    ./scripts/private_lifecycle_smoke.sh

Expected result:

    PRIVATE LIFECYCLE SMOKE PASSED

This verifies:

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

Run:

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

That guide contains deeper private lifecycle and operator setup details.

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
- Tests proving private responses omit Swarm reference headers

## Remaining security work

The next major security work should focus on delegation and authorization scope tests:

- Contract-level delegation scope tests
- Gateway delegation end-to-end tests
- Negative permission tests
- Revocation behavior tests
- Encryption version rotation design

These are the next layers needed to prove that unauthorized accounts cannot access or mutate private bucket state.
