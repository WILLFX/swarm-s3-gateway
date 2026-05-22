# Private encryption version rotation

## Current model

Private bucket records contain an `encryption_version`.

Private PUT uses the current bucket `encryption_version` when deriving:

- private object index keys
- private object payload keys
- private object payload AAD
- private object manifest keys
- private bucket manifest keys

Private bucket manifests contain object entries. Each private object entry stores the `encryption_version` that was active when that object was written.

This means object-level metadata is versioned per entry. A reader must use the object entry's stored version to derive the object key ID and read the private object manifest.

## Important limitation

The private bucket manifest itself is encrypted using the bucket `encryption_version`.

Therefore, simply incrementing the on-chain bucket `encryption_version` is not enough to rotate a populated bucket safely.

If the chain bucket version is incremented while `bucket_manifest_root` still points to a manifest encrypted with the previous version, the gateway will try to decrypt that manifest using the new version and fail.

Safe rotation needs one of these designs:

1. migrate/re-encrypt the bucket manifest under the new version at rotation time;
2. store the bucket manifest's encryption version alongside the bucket manifest root;
3. keep old bucket manifest root/version pairs as readable history;
4. intentionally treat a version bump as a new empty private namespace and document that old objects require an older root/version path.

## Current supported behavior

The current gateway supports mixed object encryption versions inside a readable private bucket manifest.

That means:

- object entries keep their own `encryption_version`;
- private object lookup derives object IDs using the entry version;
- private object manifests and payloads are decrypted using the object manifest version.

## Current unsupported behavior

The gateway does not yet provide a production-safe bucket encryption rotation workflow.

Do not expose `increment_encryption_version` as an operator/user rotation feature until the bucket manifest migration/versioning design is implemented and covered by smoke tests.

## Required future smoke test

A full rotation smoke must prove:

1. create private bucket at version 1;
2. PUT object A at version 1;
3. rotate to version 2 using the chosen migration/versioning design;
4. GET object A still succeeds;
5. PUT object B uses version 2;
6. LIST shows both objects;
7. DELETE works for both objects;
8. stale manifest roots or wrong versions fail closed.
