# Independent review package

Status: **independent review not performed**. Automated checks and this document are engineering evidence, not an external audit. No external reviewer has been contacted or represented as having approved the code.

## Review scope

- Container v1 compatibility: src/x12/vault.py and tests/vectors/v1.json.
- Chunked format, completion authentication, limits and rekey lineage: src/x12/streaming.py and docs/format-v2.md.
- Two-half Shamir composition and per-holder password envelopes.
- Signature composition, nested HPKE, peer pinning, expiration and local replay state: src/x12/transport.py and docs/device-protocol.md.
- Exclusive file publication, failure boundaries and plaintext remnants: src/x12/storage.py.
- Packaging/runtime dependencies and trust in downloaded binaries.

## Evidence available

Public synthetic v1 interoperability vector generated with x12 0.1.0 and PyCryptodome 3.24.1, checked against the upgraded implementation. Tests cover all 3-of-5 quorums, malformed inputs, password separation, large-file memory bounds, record swaps, missing footer, v1 migration, generation changes, checkpoints, real process death and simulated disk exhaustion. Device tests cover two-holder recovery, dual-signature tampering, recipient substitution, expiry, unknown requests, replay and fail-closed output errors.

The real-trace reducer preserves the observed recovery error, not a vulnerability classification. Examples and reports are synthetic and contain no user secrets.

## Questions for a reviewer

1. Do the format/domain bindings and operation bounds provide the intended integrity/confidentiality properties?
2. Is the share composition and rewrapping safe under malicious-holder and offline-guessing models?
3. Does nested HPKE and dual-signature composition have unaddressed cross-protocol or identity-binding risks?
4. Are consumption-before-publication semantics and crash remnants adequately handled?
5. Are parser resource limits and filesystem assumptions sound on each supported OS?
6. Do packaged crypto libraries include the expected native implementations and notices?

Remaining research includes true threshold decryption without file-key reconstruction and robust global freshness. They are not silently represented as finished features.
