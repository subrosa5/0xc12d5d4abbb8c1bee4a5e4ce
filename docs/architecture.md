# Architecture proposal

Status: proposal. Cryptographic format and library choices are not finalized.

## Vault

Generate a fresh random data-encryption key for each immutable vault container. Use an established AEAD construction through a maintained library. Never derive the file key directly from a human password.

The format must authenticate its version, algorithm identifier, container identifier, file metadata, chunk ordering, and completion marker where applicable. Specify key/nonce scope, maximum sizes, malformed-input handling, and truncation detection before implementing chunked encryption.

Create a new container for updates rather than modifying encrypted chunks in place. Write through a temporary file and use the platform's supported durability and atomic replacement mechanisms. Test interruption points explicitly; atomic rename alone is not a universal durability guarantee.

## Recovery

Use an established Shamir secret-sharing library to divide the random file key. Each share envelope must bind its container ID, recovery generation, index, threshold, total share count, and format version. A checksum can detect accidental damage but does not authenticate a malicious share. Authenticity and encrypted share-envelope protection must be specified before release.

Reject duplicate indices and mixed recovery generations. Final AEAD verification must reject a wrong reconstructed key. Threshold recovery reconstructs the full key on the receiving device. It is not threshold decryption or a persistent per-read approval system.

Changing participants cannot invalidate previously copied keys, plaintext, or old share sets for old containers. New membership requires a new recovery generation; revocation for future content also requires appropriate fresh keys and distribution.

## Crash lab

Run experiments against isolated synthetic fixtures and the actual vault implementation. Planned scenarios include process termination during writes, truncated or mutated containers, loss of shares, duplicated shares, concurrent operations, and restoration of old state.

The event observer must remain outside the state being rolled back when comparing activity across restoration. Observed key/nonce uniqueness is a bounded test result, not a universal proof. An offline client needs an independent freshness anchor to reliably detect a full-history rollback.

## Reproducer

Record the fixture seed, tool version, scenario, operations, expected invariant, and observed failure. Minimize scenarios while preserving the same failure predicate. Export synthetic artifacts only by default. Do not collect real vault contents, keys, shares, environment dumps, or request bodies.

## Future work

Cross-device share delivery may use a reviewed hybrid post-quantum protocol. KEMs do not authenticate participants on their own. Device identity, transcript binding, replay handling, and share protection must be specified as a complete protocol.

True threshold decryption without reconstructing a long-term private key is a separate research milestone.
