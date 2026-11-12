# Architecture v0.2

The local CLI and native desktop use the same core. No server or telemetry is involved.

- vault.py: legacy v1, strict parsing, two-half library Shamir, password-protected share envelopes and rewrapping.
- streaming.py: immutable chunked v2, completion authentication, v1 recovery, new-key generations and exact-version checkpoints.
- storage.py: private temporary files, fsync and exclusive hard-link publication, observable test boundaries.
- transport.py: protected device identities, dual signatures, nested library HPKE, expiry, pinning and fail-closed local replay state.
- desktop.py: local native create/recover/rekey/lab, with work outside the UI thread.
- recovery.py: separate recovery entry point suitable for offline native bundling.
- lab.py / traces.py: synthetic failure experiments, real process termination and fixed-operation trace reduction. No report-supplied commands run.
- tools/: OS-native packaging and binary smoke checks, including legacy recovery and GUI initialization.

See [format v1](format-v1.md), [format v2](format-v2.md), [device protocol](device-protocol.md), [security model](../SECURITY.md) and [independent review package](audit-readiness.md).

The device protocol releases a share under explicit consent. The recovering device reconstructs the whole file key. True distributed decryption is not implemented. Freshness checkpoints must remain independently trusted; restoring the checkpoint or replay ledger together with old state defeats those protections.
