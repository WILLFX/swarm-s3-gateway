# Chain Privacy Surface

This document describes what the chain exposes for private bucket state, what is intentionally protected, and what metadata leakage remains.

The chain is used as a state anchor and authorization layer. It is not the layer that makes private bucket contents private.

Private bucket privacy depends on:

- object payload encryption
- encrypted owner catalogs
- encrypted private bucket manifests
- encrypted private object manifests
- gateway authorization
- not exposing usable private Swarm references in private S3 responses

## What the chain exposes

The bucket contract intentionally exposes public state metadata:

| Surface | Exposed value | Privacy impact |
|---|---|---|
| Owner account | Account that owns or updates bucket state | Reveals that an account uses the system |
| Bucket hash | `bucket_name_hash` | Hides plaintext bucket name, but may be guessable if the bucket name is low entropy |
| Visibility flag | `is_private` | Reveals whether a bucket is marked private |
| Encryption version | `encryption_version` | Reveals version changes and rotation activity |
| Owner catalog root | `owner_catalog_root` | Public pointer to encrypted owner catalog bytes |
| Bucket manifest root | `bucket_manifest_root` | Public pointer to encrypted private bucket manifest bytes |
| Events | root updates, create/delete, version increments | Reveals update timing and activity patterns |

This is not zero-metadata privacy. A public chain can reveal when an owner updates private state, how often roots change, and which bucket hash changed.

## What the chain must not expose

The chain must not directly store or emit:

- plaintext bucket names
- plaintext object keys
- object content types
- object sizes
- private object Swarm references
- encrypted object payload references
- plaintext owner catalogs
- plaintext private bucket manifests
- plaintext private object manifests

## Current implementation position

The current implementation stores and emits roots/hashes on-chain, not plaintext private object metadata.

Private owner catalogs are serialized, encrypted, uploaded to Bee/Swarm, and then the encrypted Swarm root is anchored.

Private bucket manifests are serialized, encrypted, uploaded to Bee/Swarm, and then the encrypted Swarm root is anchored.

Private object manifests are serialized, encrypted, uploaded to Bee/Swarm, and referenced from the encrypted private bucket manifest.

This means an observer can see the chain roots, but following those roots should return encrypted bytes, not plaintext private metadata.

## Remaining metadata risks

The following risks remain and should be treated honestly:

### Bucket-name guessing

`bucket_name_hash` is owner-scoped, which is better than a global bucket-name hash. However, if an attacker knows the owner and can guess likely bucket names, low-entropy names may still be guessed by computing candidate hashes.

Examples of low-entropy names:

- private
- backup
- photos
- documents
- invoices
- client-files

A future stronger design could derive bucket IDs from a secret salt/key rather than only public owner plus bucket name.

### Timing analysis

Root updates reveal activity timing. Observers may infer when an owner creates, updates, deletes, or rotates private bucket state.

### Encrypted blob size leakage

Encryption hides contents but not necessarily byte length. Encrypted catalog or manifest size may reveal approximate object counts or growth patterns.

### Master key compromise

If the gateway master service key leaks, private manifests and private object payloads may become readable. Production deployments must protect this key using proper secret management.

### Future delegation changes

Delegation logic must not introduce plaintext object keys, raw private Swarm references, or content metadata into contract storage/events.

## Security claim

The correct claim is:

The chain leaks expected public metadata about private bucket state transitions, but current private bucket contents are not directly exposed on-chain. Private catalogs and manifests are encrypted before their Swarm roots are anchored.

The incorrect claim is:

The chain provides zero metadata leakage.
