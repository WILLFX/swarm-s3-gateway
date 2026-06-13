# Trustless Private Access Model

## Status

This document defines the trustless private-access model.

The trustless local proxy MVP path has now been implemented and live-proven locally. The live proof uses a local S3-compatible proxy, local AWS ESDK Raw RSA encryption/decryption, signed remote gateway calls, Bee ciphertext/encrypted manifest storage, and local plaintext return on GET.

The older Track A private mode remains a hardened trusted-gateway mode. It protects privacy from public S3 responses, normal catalog/listing paths, chain metadata, stale concurrent writes, and several fail-open paths, but the gateway still participates in private encryption and decryption using operator-controlled service key material.

The trustless track does not modify that existing bucket type in-place. Trustless private storage is introduced as a separate bucket type with a different security boundary.

For local startup and live demo commands, see:

    docs/runbooks/trustless-local-dev.md

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
5. Includes envelope metadata such as recipient account, encryption key version, bucket ID, opaque object context ID, and policy version.
6. Returns encrypted data-key envelopes to the `aws-esdk` flow.

AWS ESDK encryption context is authenticated metadata and may be visible to anyone with the ciphertext. For object payloads, the object context ID must therefore be an opaque locally generated value, not a plaintext object key, a caller-supplied privacy identifier, or a deterministic bucket/key hash. For manifest payloads, the local proxy uses a bucket-scoped manifest context.

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

The remote trustless gateway is owner-only in the current implementation. Current identity-contract delegation is owner-wide, not bucket-scoped, so it is not used to authorize remote trustless gateway access.

At the contract boundary, trustless-private manifest-root mutation must not fall back to owner-wide identity delegation. A configured anchor signer may update a trustless bucket root only through bucket-scoped trustless anchor delegation for the current bucket generation and required operation scope. Granting or revoking that delegation requires the caller's expected generation, state epoch, encryption version, and manifest root, then increments `bucket_state_epoch`, so stale manifest writers fail across trustless bucket policy changes. This delegation is not end-user read/write authorization and does not allow the remote gateway to serve non-owner trustless requests.

The owner or authorized writer creates envelopes for:

- The owner
- Current authorized readers
- Future bucket-scoped authorized delegates, once delegate-aware trustless authorization is implemented
- Any other policy-approved recipients

A future delegate receives access only if the delegate is authorized for the specific trustless bucket or policy scope, has a valid public encryption key registered in the identity contract, and the owner or authorized writer includes an envelope for that key.

## Upload flow

The upload path for a trustless private bucket is:

1. A normal S3 client sends a PUT request to the local proxy.
2. The local proxy authenticates or maps the local user identity.
3. The local proxy checks or fetches the bucket policy and recipient set.
4. The local proxy uses `aws-esdk` with the custom keyring to encrypt the object payload locally.
5. The custom keyring wraps the data key to the owner and authorized recipients using public encryption keys from the identity contract.
6. The local proxy generates a fresh opaque object context ID for the new object version.
7. The local proxy uploads only encrypted object bytes to the remote gateway.
8. The remote gateway stores ciphertext in Bee and returns an immutable ciphertext reference.
9. The local proxy writes the plaintext object key, opaque object context ID, ciphertext reference, and metadata into the encrypted bucket manifest locally.
10. The local proxy sends only the encrypted manifest update and manifest-root precondition to the remote gateway.
11. The remote gateway anchors CAS-protected roots on-chain.
12. The remote gateway never receives plaintext object bytes, plaintext object keys, caller-supplied object key IDs, or plaintext data keys.

## Download flow

The download path for a trustless private bucket is:

1. A normal S3 client sends a GET request to the local proxy.
2. The local proxy reads the chain-anchored encrypted manifest and decrypts it locally.
3. The local proxy resolves the object's ciphertext reference from that manifest.
4. The local proxy forwards an authorized read request containing that exact ciphertext reference to the remote gateway.
5. The remote gateway verifies authorization and returns only the referenced ciphertext object.
6. The local proxy selects an encrypted data-key envelope addressed to the local account.
7. The local proxy unwraps the data key locally.
8. The local proxy uses `aws-esdk` to decrypt the object locally.
9. The local proxy returns plaintext to the local S3 client.
10. The remote gateway never sees the plaintext response.

The remote trustless object read request does not contain the plaintext object key. The plaintext key is used only inside the local proxy after decrypting the encrypted manifest.

## List and manifest flow

For trustless private buckets, private listings must be decrypted locally.

The remote gateway may return encrypted owner catalog and bucket manifest ciphertext. The local proxy decrypts those manifests and presents S3-compatible list results to the local S3 client.

The remote gateway must not require plaintext private object names or caller-supplied object key IDs to serve trustless private list operations.

## Bucket identity privacy

Remote trustless ciphertext requests carry `bucket_id_hex`, not plaintext bucket names.

Trustless bucket IDs must be random or secret-salted opaque 32-byte identifiers. A trustless bucket create request supplies that identifier through `x-s3w-bucket-id`; the gateway rejects trustless-private creation without it instead of falling back to `bucket_name_hash(owner, bucket)`.

Legacy remote JSON fields such as `bucket`, `key`, and `object_key_id` are rejected. The plaintext S3 bucket name remains local-proxy input so the proxy can provide S3-compatible routing and decrypt the local owner catalog, but it is not serialized into the remote ciphertext gateway envelope.

## Delegation boundary and future flow

The remote trustless gateway is owner-only in the current implementation.

Current identity-contract delegation is owner-wide, not bucket-scoped. A direct gateway check against that delegation model would make a delegate authorization apply too broadly across an owner's trustless buckets. Do not wire owner-wide delegation into the trustless remote gateway path.

The bucket contract supports bucket-scoped trustless anchor delegation for manifest-root mutation by the configured anchor signer. That contract delegation is generation-bound, scope-checked, CAS-preconditioned against the current bucket record, and bumps `bucket_state_epoch` on grant or revoke. It exists to prevent direct contract calls from bypassing the owner-only remote gateway rule with owner-wide identity delegation.

Delegate-aware trustless end-user authorization is still separate. It must use bucket-scoped or policy-scoped delegation, recipient key envelopes, and local-proxy authorization before the remote gateway can authorize non-owner callers against that exact scope.

The future delegation path is:

1. Delegate registers an encryption public key in the identity contract.
2. Owner grants delegate access on-chain for a specific trustless bucket or policy scope.
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
- Owner-only authorization checks until bucket-scoped delegate authorization is implemented
- Bee storage and retrieval of ciphertext
- Chain anchoring
- CAS root updates
- Returning encrypted blobs, encrypted manifests, and encrypted envelope data
- Storing trustless object ciphertext as raw immutable Bee bytes and returning the resulting ciphertext reference
- Serving object GET and HEAD reads only for explicit ciphertext references resolved by the local proxy from the encrypted manifest

The remote gateway must not be responsible for:

- Plaintext encryption
- Plaintext decryption
- Data-key generation
- Data-key unwrapping
- Private manifest decryption
- Private owner catalog decryption
- Receiving plaintext object keys in the trustless ciphertext endpoint
- Receiving caller-supplied object key IDs as the trustless privacy primitive
- Choosing object ciphertext by mutable bucket/key pointer fallback for trustless object reads

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

The chain-anchored encrypted manifest root is the authoritative trustless bucket state. A failed manifest-root CAS can leave ciphertext objects or encrypted manifest bytes staged in Bee/Swarm, but those unanchored references must not become visible through trustless GET, HEAD, LIST, or DELETE semantics unless a later chain root anchors them.

Trustless object GET and HEAD requests must carry an explicit `ciphertext_reference_hex` resolved from the locally decrypted, chain-anchored encrypted manifest. Missing references are rejected; the remote gateway must not fall back to bucket/key pointer lookup for object reads.

Trustless object DELETE requests must carry the encrypted manifest reference that the local proxy fetched and decrypted before removing the entry. Missing expected manifest references are rejected so DELETE cannot silently overwrite a concurrent manifest root.

Trustless object PUT requests must not send plaintext object keys or caller-supplied object key IDs to the remote gateway. The local proxy generates a fresh opaque object context ID per object version, encrypts object bytes locally under that context, sends only ciphertext bytes to the remote gateway, receives an immutable ciphertext reference, and then stores the plaintext key to ciphertext reference mapping only inside the encrypted manifest.

Trustless remote gateway access is owner-only. Bucket-scoped anchor delegation does not grant remote user access. The existing owner-wide identity delegation model must not be used as the trustless remote gateway authorization check or as the contract authorization path for trustless-private manifest-root mutation.
