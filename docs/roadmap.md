# Roadmap

All milestones below are planned, not implemented.

## 0. Specify

- [ ] Define adversaries, trust boundaries, and recovery guarantees.
- [ ] Select maintained AEAD and Shamir libraries after review.
- [ ] Specify the container and share-envelope formats.
- [ ] Define memory, file-size, nonce, and malformed-input limits.

## 1. Offline CLI

- [ ] Create an encrypted immutable container.
- [ ] Export protected recovery shares with configurable quorum.
- [ ] Recover using a standalone command.
- [ ] Verify round trips and rejection of corrupt or mismatched inputs.

## 2. Failure testing

- [ ] Exercise termination at write boundaries and truncated files.
- [ ] Exercise missing, duplicate, modified, and mixed-generation shares.
- [ ] Exercise concurrent operations and state restoration.
- [ ] Observe AEAD key/nonce use without exporting raw keys.

## 3. Reproducible reports

- [ ] Record deterministic synthetic scenarios.
- [ ] Reduce failing sequences while retaining the failure.
- [ ] Export a replay command and a human-readable report.
- [ ] Run regression scenarios in CI.

## 4. Interface and research

- [ ] Add a simple local interface once the CLI format is stable.
- [ ] Evaluate QR recovery artifacts and offline usability.
- [ ] Design authenticated cross-device share delivery.
- [ ] Evaluate hybrid post-quantum transport and external security review.
