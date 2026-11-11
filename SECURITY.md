# Security model and reporting

Version 0.1.0 is experimental. The container composition has not received an independent audit. Initial development targets macOS and Linux. Use synthetic data during evaluation.

## Assets and trust

Assets are plaintext, random AES file keys, recovery shares and passwords. The design aims to protect contents from someone possessing a container without a quorum of valid shares and the recovery password. Fewer than the threshold number of decrypted Shamir shares should not reveal the uniformly random file key under the secret-sharing assumptions.

The creating and recovering devices are trusted with full keys and plaintext. The OS, Python runtime, PyCryptodome, dependencies and CSPRNG are trusted. The filesystem must support exclusive hard-link publication.

## Implemented checks

- AES-256-GCM authenticates file content and its complete versioned prefix.
- Share AES-GCM authenticates payload and metadata with a password-derived key.
- Parsing bounds lengths and parameters, rejects duplicate fields, malformed encodings, trailing data, mixed headers and repeated share indices.
- Plaintext output is created only after full file authentication.
- Existing output files and symlinks are never replaced.
- POSIX output files use 0600; bundle directories use 0700.
- Reports use synthetic data and never execute JSON-supplied commands.

## Limits

- The common password is an additional recovery dependency. Losing it loses access. Offline guessing against a stolen share is possible; scrypt cannot fix weak passwords.
- Password holders can forge envelopes. These are not participant signatures. Malicious shares can deny recovery; all supplied shares must pass. Final file AEAD verification prevents unauthenticated plaintext output.
- A quorum can retain recovered keys/plaintext. There is no persistent per-read approval, remote erasure or revocation of old copies.
- Old containers/share sets remain valid. Integrity checks cannot establish freshness of an entirely restored valid history.
- Compromised endpoints, malware, screen capture, swap, core dumps, malicious dependencies and side-channel attacks are outside the boundary. Python cannot reliably zeroize secret buffers.
- Size and quorum metadata are public. Source names are not stored, but CLI paths may remain in shell history.
- Abrupt termination can leave private `.x12-*` temporary files; recovery temporaries contain authenticated plaintext. Secure deletion is not promised.
- Creation is not a multi-file transaction. `COMPLETE` is written last. Incomplete directories are not complete backups, and sources are never deleted.
- Files are loaded into memory, with a 64 MiB limit. There is no streaming or in-place update.
- Crash tests cover specific scenarios, not all interruption points, hardware power loss, unknown platforms or absolute security.
- The intentionally broken nonce-counter demo is not used by the vault. Fixture seeds never seed cryptographic randomness.

## Reporting

Use GitHub private vulnerability reporting if enabled. Never post real keys, shares, passwords, plaintext or personal data in public issues. If private reporting is unavailable, request a private contact route without publishing exploit details.

Include the version, affected component, expected property and a synthetic reproducer. A passing lab report is not a security certificate.
