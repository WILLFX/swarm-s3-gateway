# Trustless Local Proxy

This package is the local S3-compatible proxy for TrustlessPrivate buckets.

The proxy is the client-side trust boundary. It is responsible for local plaintext handling, client-side encryption and decryption, local private-key custody, recipient envelope creation, and forwarding ciphertext-only requests to the remote gateway.

The remote gateway must never receive plaintext object bytes, plaintext data keys, private encryption keys, decrypted owner catalogs, decrypted bucket manifests, or decrypted object manifests for TrustlessPrivate buckets.

## MVP scope

The minimum viable proxy will support:

- Local S3-compatible PUT, GET, HEAD, DELETE, and ListObjectsV2
- Trustless private bucket creation
- `aws-esdk` payload encryption and decryption
- A custom `aws-esdk` keyring for recipient envelopes
- Identity-contract lookup for recipient public encryption keys
- Local encrypted keystore for the client private encryption key
- Encrypted owner catalog and bucket manifest handling
- Ciphertext-only forwarding to the remote gateway
- Clear rejection when a recipient has no registered public encryption key

## Non-goals for MVP

The MVP does not implement MPC custody, hardware wallets, secure enclaves, browser-extension custody, automatic migration from trusted-gateway private buckets, or offline sharing.

## Package status

This directory currently contains the proxy scaffold and surface guards only. Real encryption, remote forwarding, local keystore, and keyring implementation will land in separate PRs.
