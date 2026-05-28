# Trustless Proxy Failure Modes and Implementation Plan

This document explains the failure modes the trustless local proxy must prevent, what the boundary work was protecting against, and where production implementation begins.

## Core invariant

Plaintext is local. Ciphertext is remote. Gateway plaintext access is forbidden. Failure must be closed, not silently downgraded.

## Main failure mode

A bucket is called trustless-private, but plaintext object bytes, plaintext manifests, plaintext data keys, local private keys, or decryptable private metadata still reach the remote gateway.

## Failure modes

### 1. PUT leaks plaintext to the gateway

Bad behavior: local proxy receives plaintext and forwards plaintext to the remote gateway.

Required behavior: local proxy encrypts locally and the remote gateway receives ciphertext only.

Already guarded by: PUT-only local plaintext boundary, EncryptObjectLocally stage, SendCiphertextOnlyGatewayRequest stage, gateway_plaintext_access false.

Still needed: real AWS Encryption SDK encryption, real ciphertext-only remote request, end-to-end PUT test.

### 2. GET depends on gateway plaintext

Bad behavior: gateway decrypts object and returns plaintext.

Required behavior: gateway returns ciphertext, local proxy decrypts, client receives plaintext locally.

Already guarded by: GET ciphertext fetch, DecryptObjectLocally stage, ReturnLocalPlaintext stage.

Still needed: real ciphertext GET client, real local decrypt, end-to-end GET test.

### 3. Manifest is plaintext at the gateway

Bad behavior: private object names, metadata, and ciphertext refs are stored in a plaintext manifest.

Required behavior: manifest is serialized locally, encrypted locally, and stored remotely only as encrypted bytes.

Already guarded by: ReadEncryptedManifest, DecryptManifestLocally, MutateManifestLocally, EncryptManifestLocally.

Still needed: canonical manifest JSON codec, encrypted manifest persistence, manifest encryption and decryption.

### 4. LIST leaks object names

Bad behavior: LIST asks the gateway for plaintext object names.

Required behavior: gateway returns encrypted manifest and local proxy lists entries locally after decrypting.

Already guarded by: LIST route to encrypted manifest fetch and local manifest list boundary.

Still needed: real encrypted manifest fetch and real local listing over serialized manifest data.

### 5. DELETE sends plaintext manifest update

Bad behavior: local proxy mutates the manifest and sends plaintext manifest to the gateway.

Required behavior: local proxy decrypts, mutates, re-encrypts, and sends encrypted manifest update only.

Already guarded by: MutateManifestLocally, EncryptManifestLocally, DeleteCiphertextObject remote action.

Still needed: real encrypted manifest update request and end-to-end DELETE test.

### 6. Remote gateway client accidentally sends plaintext

Bad behavior: future HTTP client serializes plaintext_body into the remote request.

Required behavior: remote client rejects any request with plaintext payload present.

Already guarded by: TrustlessRemoteGatewayExecutor and CiphertextGatewayBoundary.

Still needed: real ciphertext-only HTTP client and tests inspecting outbound body.

### 7. AWS Encryption SDK keyring leaks key material

Bad behavior: plaintext data key or local private recipient key reaches the gateway.

Required behavior: data keys and private keys stay local. Gateway receives ciphertext and encrypted key material only.

Already guarded by: TrustlessRecipientKeyring trait, RecipientEnvelopeContext, LocalPrivateKeySelection boundary.

Still needed: real AWS Encryption SDK for Rust integration and tests proving key material is not serialized remotely.

### 8. Local keystore exposes raw private keys

Bad behavior: private key is stored raw, logged, or attached to remote request context.

Required behavior: local keystore stores encrypted private key blobs and unlocks only locally.

Already guarded by: LocalPrivateKeySelection exposes encrypted_private_key_blob and storage_label, not plaintext private key.

Still needed: real local keystore file format, unlock flow, and secret logging audit.

### 9. Recipient resolver silently falls back insecurely

Bad behavior: missing or disabled recipient key silently falls back to a dev key.

Required behavior: missing, disabled, empty, stale, or wrong-type recipient keys fail closed.

Already guarded by: RecipientEnvelopeBuilder fail-closed behavior and no silent dev signer guard.

Still needed: real identity contract recipient-key read and enabled/version checks.

### 10. Trustless bucket type is not anchored

Bad behavior: gateway treats a bucket as trustless-private without chain confirmation.

Required behavior: trustless bucket creation anchors bucket type and policy on-chain.

Already guarded by: CreateTrustlessBucketAnchor stage, bucket type contract surface, gateway bucket type route guards.

Still needed: real bucket create anchor call and real bucket type lookup in local proxy path.

### 11. HTTP request mapping misroutes plaintext

Bad behavior: GET with body is treated like PUT, or unsupported methods sneak plaintext through.

Required behavior: only PUT object accepts local plaintext body. Other methods reject plaintext body.

Already guarded by: LocalTrustlessHttpMapper, LocalTrustlessHttpHandler, LocalTrustlessServer scaffold.

Still needed: real HTTP server binding, request body size enforcement, and S3-compatible response mapping.

### 12. Logs or errors expose secrets

Bad behavior: plaintext object bytes, data keys, private keys, or decrypted manifests appear in logs or errors.

Required behavior: logs may include operation, status, hashes, versions, and safe refs only.

Still needed: secret-safe logging policy and tests or guards against obvious secret logging fields.

## Boundary stop line

Boundary work is sufficient when PUT cannot route plaintext remotely, GET cannot rely on gateway plaintext, LIST cannot use plaintext remote manifest, DELETE cannot send plaintext manifest updates, remote gateway boundary rejects plaintext payloads, local keystore model does not expose plaintext private keys to remote paths, recipient key builder fails closed, and HTTP mapper rejects plaintext outside PUT.

This stop line has mostly been reached. New PRs should now prefer real implementation over more surface scaffolding.

## Production implementation order

1. Implement trustless manifest JSON codec.
2. Implement local keystore file format and safe loading.
3. Implement recipient key resolver from identity contract reads.
4. Implement ciphertext-only remote gateway HTTP client.
5. Integrate real AWS Encryption SDK for Rust keyring.
6. Add real local HTTP server binding.
7. Add end-to-end PUT to encrypted remote payload to GET local decrypt test.
8. Add secret and logging safety audit.

## PR rule going forward

Every implementation PR must state:

- Failure mode being closed
- Production gap being implemented
- What remains fake
- Next implementation dependency

## Current decision

The skeleton and boundary phase is frozen unless a real implementation exposes a missing safety boundary.

The next real implementation is: Implement trustless manifest JSON codec.
