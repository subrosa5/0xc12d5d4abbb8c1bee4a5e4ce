# Security model v0.2.0

Experimental software. The container and device protocol compositions have not received independent security review. [Review materials](docs/audit-readiness.md) are prepared; they are not an audit report.

## Trust and assets

Protect plaintext, random AES file keys, recovery shares, passwords and device identity keys. Creating and recovering devices see full file keys/plaintext. The OS, Python/runtime, PyCryptodome, dependency supply chain, CSPRNG and filesystem are trusted. A quorum of decrypted Shamir shares reconstructs the file key. The application does not implement true threshold decryption or perpetual per-read consent.

## Container and recovery checks

AES-GCM authenticates the full prefix, indexed chunk records and completion marker. Each generation uses a fresh file key. V2 is bounded to 1 TiB, with fixed 1 MiB chunks and bounded memory. V1 retains its original 64 MiB memory bound. Strict schemas, parameter/encoding limits, duplicate-index checks and exact generation binding reject malformed input. Every supplied share must be valid; malicious participants can deny recovery. The tool does not automatically try all subsets.

Each share may use an independent password and salt. Offline guessing against a stolen envelope remains possible; scrypt increases cost, but weak/lost passwords are not repaired by secret sharing. Share envelopes are authenticated by their password, not participant signatures. Final file authentication rejects incorrect reconstruction.

## Storage and crash limits

Exclusive hard-link publication never replaces an existing destination, including symlinks. POSIX files are 0600 and bundle directories 0700. The filesystem must support the operation. A container and its shares are not one filesystem transaction: COMPLETE is written last. Sources are retained. Interrupted creation can leave an incomplete directory.

V2 verifies each chunk before writing it to a private temporary file; the final path is published only after the completion tag and EOF validate. A crash can leave authenticated plaintext chunks in .x12-* temporaries. Secure deletion and reliable Python memory zeroization are not provided. Swap, core dumps and screen capture are host concerns.

Five controlled process-termination boundaries and simulated disk errors are tested. They do not certify physical power-loss durability, every filesystem/ACL configuration or a hostile endpoint. Source changes detected during creation/rekey cause rejection; this is not a snapshot service against a malicious OS.

## Version changes and checkpoints

Rekeying creates a new file key, recovery ID, shares and version lineage. Old shares do not unlock the new generation. Old copied containers, keys and plaintext remain valid; revocation cannot erase them.

An independently retained checkpoint commits to exact container bytes. Recovery checks the bytes actually consumed before publication. Checkpoints do not authenticate unknown input or determine global latest state. An attacker who rolls back both a vault and its trusted checkpoint can bypass this local protection.

## Device handoff

Fingerprints must be independently verified by users. Device identities represent key possession, not certified real-world identities. Both Ed25519 and ML-DSA-65 signatures are required. Share values use nested library HPKE with ML-KEM-768 and X25519. Fixed context strings and signed metadata bind request, sender, recipient, expiry and encapsulations. This application composition is experimental; no FIPS validation or audited messaging-protocol claim is made.

Releasing a share requires explicit confirmation. The receiver rewraps it under a local password; holder passwords are not transferred. Valid requests expire within one hour under a trusted local wall clock. Stored capsules lack forward secrecy against later recipient identity compromise.

The requester ledger consumes a request before publication. Output failure afterward requires a fresh request. Rolling back the ledger can undo replay protection; keep it independent of rolled-back vault storage. No global revocation or distributed replay service is implemented. The software does not send messages to other people itself.

## Diagnostics and dependencies

Lab/reducer inputs are fixed synthetic fixtures. Reports contain no user vaults, keys, passwords, environment dumps or commands to execute. Expected rejection of corruption is not labeled a vulnerability. Fixture seeds never seed cryptographic randomness. Native executables bundle a runtime and crypto library; verify their provenance. They are not Developer-ID signed/notarized.

## Reporting

Use GitHub private vulnerability reporting if available. Never post real keys, shares, passwords or private files in public issues. If unavailable, request a private contact route without exposing exploit details. Include the version, expected property and a synthetic reproducer.
