# Gateway Idempotency

## Scope

Gateway mutation routes accept `x-s3gw-idempotency-key` as an optional retry key.

The key must be a 32-byte high-entropy hex value. If the header is present, the gateway requires `S3GW_IDEMPOTENCY_JOURNAL_PATH` to point at a durable JSONL journal. Requests with an idempotency key fail closed when the store is not configured or cannot append the reservation before side effects begin.

This is gateway-local idempotency. It protects retries that return to the same gateway journal. It does not provide global multi-gateway idempotency unless a later design anchors operation receipts in shared canonical state.

## Covered Mutations

The current gateway-local layer covers:

- bucket create and delete;
- public object PUT and DELETE;
- trusted-gateway private object PUT and DELETE;
- trustless ciphertext object PUT;
- trustless encrypted-manifest PUT and DELETE.

GET, HEAD, and LIST do not reserve idempotency keys because they do not mutate canonical state.

## Journal Semantics

The journal records `started`, `succeeded`, and `failed` events.

A new key and request digest reserves the operation before Bee writes or chain anchors are attempted. A retry with the same key while the operation is pending returns an in-progress conflict. A retry with the same key and a different digest returns a conflict. A retry with the same key and same digest after a durable success record replays the stored success response.

CAS is never bypassed. Fresh mutations still observe the current chain state, build the candidate state from that observation, and submit the normal contract preconditions. Idempotency only decides whether a completed result can be replayed or whether a key is already bound to another request.

## Privacy Boundary

The durable request digest is typed and domain-separated. It stores the digest, not plaintext object keys or plaintext request bodies.

For private object operations, replay records do not persist encrypted Swarm references that the normal response intentionally omits. For trustless private bucket creation, replay records do not persist the S3 `Location` header because that header contains the plaintext bucket name.

The trustless ciphertext endpoint computes idempotency digests over ciphertext-side fields such as bucket ID, ciphertext bytes, encrypted manifest bytes, ciphertext references, and manifest-root preconditions. It must not use plaintext bucket names, plaintext object keys, or caller-supplied object key IDs.

## Remaining Global Layer

Global multi-gateway idempotency requires canonical operation receipts. Acceptable future designs include chain-anchored operation receipts or manifest-anchored receipts that all participating gateways or local proxies can verify.

Do not claim multi-gateway idempotency from the gateway-local journal alone. A retry routed to a different gateway cannot see another gateway's local JSONL journal.
