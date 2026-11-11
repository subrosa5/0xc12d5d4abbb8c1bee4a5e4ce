# Roadmap

## v0.1.0 — implemented

- [x] Describe trust boundaries, bounded format and recovery limits.
- [x] Use PyCryptodome for AES-GCM, scrypt and Shamir.
- [x] Create immutable containers and protected shares with configurable quorum.
- [x] Recover offline through a separate CLI process.
- [x] Reject corrupt, duplicate, insufficient and mixed-vault inputs.
- [x] Exercise process termination before publication and concurrent encryption.
- [x] Check restored immutable snapshots and no-overwrite behavior.
- [x] Generate readable/JSON reports and replay synthetic experiments.
- [x] Reduce an intentionally broken nonce-counter demonstration.
- [x] Add tests and CI for Python 3.11–3.13.

## Next engineering milestones

- [ ] Independent security review and expanded protocol vectors.
- [ ] More interruption points and supported filesystem testing.
- [ ] Minimize real-vault failures beyond the demonstration model.
- [ ] Separate offline recovery distribution and interoperability fixtures.
- [ ] Independently protected shares for different holders.
- [ ] Versioned rekeying and holder replacement.
- [ ] Specified streaming format beyond 64 MiB.
- [ ] Local interface after protocol stabilization.

## Research milestones

- [ ] Authenticated cross-device delivery and approval requests.
- [ ] Hybrid post-quantum transport with identity binding.
- [ ] Freshness anchors to detect old valid state.
- [ ] True threshold decryption without private-key reconstruction.
- [ ] Adapter API for testing external applications.

Future items are not current guarantees.
