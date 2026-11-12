# Experimental device approval protocol v1

This application protocol is not independently audited. It uses PyCryptodome's ML-KEM-768 and X25519 HPKE plus both ML-DSA-65 and Ed25519 signatures. The nested encryption uses the library's two independent HPKE layers; it is not a custom KEM combiner. The ML-KEM HPKE integration follows the library's draft-based suite. It is not a claim of protocol certification.

## Identity and trust

Each device has four independent key pairs. Public JSON contains exactly format=x12-device, integer version=1 and padded Base64 public keys: mlkem (1184 raw bytes), x25519 (32), mldsa (1952), ed25519 (32). The fingerprint is SHA-256 of the canonical public JSON. Private seeds are stored together under scrypt/AES-GCM with authenticated public metadata. Derived public keys are checked after unlocking.

Verify the full fingerprint with the other person through an independent authenticated channel. Every handoff command requires `--peer-fingerprint`. Loading a public file by itself does not establish a person's identity.

```sh
x12 identity --out requester-device
x12 identity --out holder-device
x12 fingerprint holder-device/identity.public.json
```

Keep private identities and passwords private; exchange only public files and verified fingerprints.

## Request

```sh
x12 request --identity requester-device/identity.private.json \
  --peer-public holder-device/identity.public.json --peer-fingerprint FULL_HOLDER_FINGERPRINT \
  --vault vault.x12 --state requester-ledger.sqlite --out request.json
```

The request body binds a random 16-byte id, requester and holder fingerprints, vault_id, exact prefix hash, whole-vault hash, threshold, total shares and expiration. Lifetime defaults to 600 seconds and is bounded to 3600. Local wall-clock integrity is assumed. Both signatures cover canonical body bytes, with context `x12/device-file-protocol/v1`. The requester records the request's signed-envelope hash in a local ledger before publishing it.

## Explicit approval

```sh
x12 approve --identity holder-device/identity.private.json \
  --peer-public requester-device/identity.public.json --peer-fingerprint FULL_REQUESTER_FINGERPRINT \
  --request request.json --share holder-share.x12share --confirm --out approval.json
```

The holder unlocks their device identity and share with their own passwords. The tool checks both request signatures, recipient, expiry and share-to-vault binding. `--confirm` explicitly authorizes release to this requester.

The payload is the unwrapped 32-byte share value plus its authenticated metadata. It is encrypted first with recipient ML-KEM-768 HPKE, then the inner ciphertext is encrypted with recipient X25519 HPKE. Both use AES-256-GCM. Fixed info strings distinguish layers and include SHA-256 of the approval metadata. The outer AAD also binds the inner KEM encapsulation. Approval metadata binds request id, signed-request hash, sender, recipient and expiry. Both holder signatures cover the complete encrypted response, including both encapsulations.

## Receive

```sh
x12 receive --identity requester-device/identity.private.json \
  --peer-public holder-device/identity.public.json --peer-fingerprint FULL_HOLDER_FINGERPRINT \
  --request request.json --capsule approval.json --state requester-ledger.sqlite \
  --out received-share.x12share
```

The receiver verifies both signature layers, exact request context, expiry, both HPKE layers and the share binding, then rewraps the value under a new local password. The holder's password is never transmitted. The approved share remains bound to its original container and index.

The ledger uses an immediate SQLite transaction to consume the request **before** output publication. A crash or disk failure afterward can consume the request without producing a share; issue a fresh request. A forged or unauthenticated response does not consume it. Retain the ledger outside rolled-back vault state. Rolling back the ledger can undo its replay protection. There is no distributed global replay service.

## Bounds and limits

Messages are at most 64 KiB, with strict schemas, fixed algorithms, bounded encodings and no algorithm negotiation. Requests/capsules are files, not network endpoints. The implementation does not transmit files or contact other participants itself.

Approval releases a share, not a revocable per-read capability. A quorum can retain recovered keys/plaintext. Stored capsules do not have forward secrecy against later recipient identity-key compromise. There is no certificate authority or revocation registry. Physical phones do not have a dedicated app in this release; any compatible device can use the file protocol. The GUI currently covers vault/recovery/rekey/lab; device handoff is a CLI workflow.
