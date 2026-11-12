# Delivery status

## v0.2.0 engineering

- [x] Backward-compatible standalone offline recovery command and native packaging.
- [x] Independent password protection for each holder's share.
- [x] Streaming v2 format, bounded memory and final completion authentication.
- [x] Fresh-key rekeying with new holder sets and generation lineage.
- [x] Independently retained exact-version checkpoints.
- [x] Native desktop for create/recover/rekey/lab.
- [x] Fingerprint-pinned signed requests and explicit device approvals.
- [x] Library ML-KEM/X25519 layered HPKE and ML-DSA/Ed25519 signatures.
- [x] Expiry and one-use local requester ledger.
- [x] Five real process-death boundaries and simulated disk-full tests.
- [x] Reduction/replay of actual synthetic streaming-recovery errors.
- [x] v1 interoperability fixture and protocol/security documentation.
- [x] CI and native build/smoke-test workflows.

## Outside a self-reviewed software delivery

- [ ] Independent external security audit (review package prepared).
- [ ] Developer-ID signing/notarization for public OS trust integration.
- [ ] Dedicated mobile applications and GUI for device handoff.
- [ ] General-purpose instrumentation of arbitrary external applications.

## Research, not current guarantees

- [ ] True threshold decryption without reconstructing a file key.
- [ ] Global freshness/anti-rollback without a separately trusted anchor or service.
- [ ] Forward secrecy for asynchronous stored approval capsules.

Old copied data cannot be retroactively erased or made unreadable by rekeying. Test success is not a security proof.
