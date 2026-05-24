# Trustless Private Access Model

## Status

This document defines the target trustless private-access model.

The current Track A private mode is a hardened trusted-gateway mode. It protects privacy from public S3 responses, normal catalog/listing paths, chain metadata, stale concurrent writes, and several fail-open paths, but the gateway still participates in private encryption and decryption using operator-controlled service key material.

The trustless track does not modify that existing bucket type in-place. Trustless private storage is introduced as a new bucket type with a different security boundary.

## Bucket types

The system has three conceptual bucket modes:

1. Public bucket
2. Trusted-gateway private bucket
3. Trustless private bucket

### Public bucket

Public buckets may expose plaintext object data and public metadata through normal S3-compatible routes.

### Trusted-gateway private bucket

Trusted-gateway private buckets are the current Track A private buckets.

The gateway encrypts and decrypts private payloads and manifests using gateway-held service key material. This mode is useful for compatibility and server-side privacy controls, but it is not trustless because the gateway can recover plaintext.

### Trustless private bucket

Trustless private buckets are a new bucket type.

For trustless private buckets, the remote gateway must not be able to decrypt private object payloads, object manifests, bucket manifests, owner catalogs, or data encryption keys.

The gateway may authenticate requests, verify authorization, store ciphertext, return ciphertext, and anchor CAS-protected roots on-chain, but privacy must not depend on gateway honesty.

## Chosen architecture

Trustless private mode uses:

1. A local S3-compatible proxy
2. Client-side encryption and decryption
3. `aws-esdk` as the encryption library
4. A custom `aws-esdk` keyring
5. Recipient public encryption keys registered in the identity contract
6. Encrypted data-key envelopes for each authorized recipient

The local proxy is the trust boundary. The remote gateway is not trusted with plaintext or plaintext keys.

## Why aws-esdk

The trustless track should not define its own object encryption format by manually specifying low-level cryptographic primitive combinations.

Instead, trustless private objects use `aws-esdk` for envelope encryption, message framing, authenticated encryption format, data-key handling, and algorithm-suite selection.

The project-specific logic lives in a custom keyring, not in a custom object cipher format.

## Custom keyring model

The local proxy uses a custom `aws-esdk` keyring.

On encryption, the keyring:

1. Receives or generates data-key material through the `aws-esdk` encryption flow.
2. Looks up authorized recipients for the bucket or object.
3. Fetches each recipient's registered public encryption key from the identity contract.
4. Wraps the data key into encrypted data-key envelopes for those recipients.
5. Includes envelope metadata such as recipient account, encryption key version, bucket ID, object key ID, and policy version.
6. Returns encrypted data-key envelopes to the `aws-esdk` flow.

On decryption, the keyring:

1. Reads encrypted data-key envelopes from the encrypted message or associated manifest.
2. Finds envelopes addressed to the local client's account and encryption key version.
3. Uses the local proxy's private encryption key to unwrap the data key.
4. Gives the unwrapped data key back to `aws-esdk`.
5. Never sends the plaintext data key to the remote gateway.

## Client private encryption key

The client's private encryption key lives client-side.

For the first trustless implementation, it lives in the local proxy's local keystore.

The MVP keystore may use an encrypted file or OS keyring-backed storage. Hardware wallets, secure enclaves, browser extensions, and MPC-based custody are future key-provider backends, not the first implementation target.

The remote gateway never receives the client's private encryption key.

## Public encryption key registry

The identity contract must expose a public encryption key registry.

The registry binds:

- Substrate account ID
- Encryption public key
- Encryption key version
- Key status
- Optional expiry or rotation metadata

The registration must be authorized by the account that owns the identity. The gateway must not be able to register or substitute a delegate's encryption public key without the delegate's authorization.

This registry is required because delegation currently grants access to Substrate account IDs, but recipient key envelopes require encryption public keys.

## How an authorized client gets the data key

Private object data is encrypted client-side with envelope encryption.

The authorized client can decrypt because one encrypted data-key envelope is addressed to that client's registered encryption public key.

The gateway and unauthorized users see only ciphertext and encrypted data-key envelopes.

The owner or authorized writer creates envelopes for:

- The owner
- Current authorized readers
- Current authorized delegates
- Any other policy-approved recipients

A delegate receives access only if the delegate has a valid public encryption key registered in the identity contract and the owner or authorized writer includes an envelope for that key.

## Upload flow

The upload path for a trustless private bucket is:

1. A normal S3 client sends a PUT request to the local proxy.
2. The local proxy authenticates or maps the local user identity.
3. The local proxy checks or fetches the bucket policy and recipient set.
4. The local proxy uses `aws-esdk` with the custom keyring to encrypt the object payload locally.
5. The custom keyring wraps the data key to the owner and authorized recipients using public encryption keys from the identity contract.
6. The local proxy builds encrypted object and bucket manifest updates.
7. The local proxy sends only ciphertext, encrypted manifests, encrypted data-key envelopes, and anchor instructions to the remote gateway.
8. The remote gateway stores ciphertext in Bee.
9. The remote gateway anchors CAS-protected roots on-chain.
10. The remote gateway never receives plaintext object bytes or plaintext data keys.

## Download flow

The download path for a trustless private bucket is:

1. A normal S3 client sends a GET request to the local proxy.
2. The local proxy forwards the authorized ciphertext request to the remote gateway.
3. The remote gateway verifies authorization and returns ciphertext plus required encrypted manifest or envelope data.
4. The local proxy selects an encrypted data-key envelope addressed to the local account.
5. The local proxy unwraps the data key locally.
6. The local proxy uses `aws-esdk` to decrypt the object locally.
7. The local proxy returns plaintext to the local S3 client.
8. The remote gateway never sees the plaintext response.

## List and manifest flow

For trustless private buckets, private listings must be decrypted locally.

The remote gateway may return encrypted owner catalog and bucket manifest ciphertext. The local proxy decrypts those manifests and presents S3-compatible list results to the local S3 client.

The remote gateway must not require plaintext private object names to serve trustless private list operations.

## Delegation flow

The delegation path is:

1. Delegate registers an encryption public key in the identity contract.
2. Owner grants delegate access on-chain.
3. Owner or authorized writer fetches the delegate's registered public encryption key.
4. Owner or authorized writer creates an encrypted data-key envelope for the delegate.
5. Remote gateway stores or anchors the encrypted envelope but cannot decrypt it.
6. Delegate's local proxy can decrypt only envelopes addressed to the delegate's registered key.
7. Revocation blocks future authorization and future envelopes.

## Revocation and rotation

Revocation cannot make already-downloaded ciphertext or plaintext unknown again.

Revocation protects future access.

After revocation:

1. Owner rotates the affected bucket, manifest, or object key material.
2. Owner re-encrypts affected manifests and, where required, affected objects.
3. Owner creates new encrypted data-key envelopes only for remaining authorized recipients.
4. CAS-protected roots are updated on-chain.
5. Revoked clients cannot decrypt new versions unless they receive new envelopes.

## Local proxy MVP scope

The minimum viable local proxy supports:

1. Local S3-compatible endpoint for PUT, GET, HEAD, DELETE, and ListObjectsV2
2. Trustless private bucket create flow
3. Trustless private object PUT with `aws-esdk` encryption
4. Trustless private object GET with `aws-esdk` decryption
5. Local encrypted keystore for the client's private encryption key
6. Identity-contract lookup for recipient public encryption keys
7. Custom `aws-esdk` keyring for recipient envelopes
8. Encrypted owner catalog and bucket manifest handling
9. Remote gateway forwarding for ciphertext storage and chain anchoring
10. Clear rejection when a recipient has no registered public encryption key

The MVP does not need to support MPC, hardware wallets, secure enclaves, browser-extension custody, transparent migration from trusted-gateway private buckets, or offline sharing.

## Remote gateway role

For trustless private buckets, the remote gateway is responsible for:

- SigV4 authentication
- Authorization checks
- Bee storage and retrieval of ciphertext
- Chain anchoring
- CAS root updates
- Returning encrypted blobs, encrypted manifests, and encrypted envelope data

The remote gateway must not be responsible for:

- Plaintext encryption
- Plaintext decryption
- Data-key generation
- Data-key unwrapping
- Private manifest decryption
- Private owner catalog decryption

## Compatibility model

Trustless private S3 compatibility is provided by the local proxy, not by the remote gateway returning plaintext.

Normal S3 tools can point to the local proxy. The local proxy makes encryption and decryption transparent to those tools.

Remote gateway endpoints for trustless private buckets are ciphertext endpoints from the privacy perspective.

## Migration boundary

Trusted-gateway private buckets and trustless private buckets are separate bucket types.

A trusted-gateway private bucket must not silently become a trustless private bucket because the key ownership model is different.

Migration requires an explicit client-side re-encryption process:

1. Authorized client reads plaintext from trusted-gateway private bucket.
2. Local proxy encrypts data into trustless format using `aws-esdk`.
3. New trustless bucket roots and manifests are anchored.
4. Old trusted-gateway private bucket remains separate until explicitly deleted.

## Security invariant

For trustless private buckets, the gateway must be able to prove authorization and store or return ciphertext, but it must not be able to derive or recover plaintext private data, plaintext private manifests, plaintext owner catalogs, or plaintext data keys.
