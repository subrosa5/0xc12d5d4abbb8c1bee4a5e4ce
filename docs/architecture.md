# Architecture

Status: experimental implementation v0.1.0. See [the format](format-v1.md) and [security model](../SECURITY.md).

## Vault core

`src/x12/vault.py` owns bounded parsing, AES-256-GCM and protected recovery shares. PyCryptodome provides the primitives, including Shamir over GF(2^128).

Each immutable container has a fresh random 32-byte file key and a random 12-byte nonce. The whole file, up to 64 MiB, is one AEAD message; the prefix is associated data. There is no persisted counter or chunk update API. Source names and paths are not recorded.

Two independent Shamir polynomials share the two 16-byte halves at matching indices. Each participant gets both values. Independent scrypt salts derive share-wrapping keys from a common password. Share AES-GCM authenticates payloads and metadata. A password holder can create an envelope; this is not identity authentication.

Recovery validates all provided envelopes, rejects duplicate indices and mixed generations, reconstructs the key and verifies the file before returning plaintext. It does not automatically exclude malicious shares.

## Storage and CLI

`src/x12/storage.py` bounds reads and publishes an fsynced temporary file using an exclusive hard link. Existing files and symlinks are not replaced. Same-filesystem hard-link support is required. POSIX file mode is 0600. Durability and ACL behavior remain platform-dependent.

`src/x12/cli.py` creates a new 0700 directory and writes `COMPLETE` last. This is not a multi-file transaction. Crashes can leave incomplete directories or temporary files. The source is never deleted. Recovery authenticates data before writing a plaintext temporary output.

## Crash lab and reproducer

`src/x12/lab.py` creates synthetic fixtures and runs fixed named experiments. OS/library randomness generates cryptographic material; the replay seed controls only public fixture data.

The separate interruption worker is killed after file fsync but before publication. This tests one boundary, not physical power loss. Concurrent creation observes key hashes and nonces only in memory. Old immutable snapshots intentionally remain readable; this does not establish freshness.

Replay JSON supplies only a validated seed and tool version, never executable commands. Replay regenerates randomness. A deletion reducer produces 1-minimal traces for an intentionally broken nonce-counter model. Minimizing arbitrary real-vault failures and external-app instrumentation remain future work.

## Future work

Cross-device delivery, independent holder passwords, rekeying, streaming, an interface and hybrid post-quantum transport require separate protocol design. KEMs alone do not authenticate participants. True threshold decryption without private-key reconstruction is a separate research milestone.
