# Security

This repository is a design scaffold. No cryptographic implementation has been released or audited. Use synthetic data during development.

## Reporting

Use GitHub's private vulnerability reporting if enabled. Do not put real private keys, recovery shares, plaintext, or personal data in public issues. If private reporting is unavailable, open a public issue requesting a private contact route without disclosing exploit details or secrets.

## Design requirements

- Use established cryptographic primitives through maintained libraries.
- Explicitly specify key/nonce uniqueness, authentication, recovery, and update behavior.
- Keep failure-test fixtures separate from real user data.
- Generate diagnostic bundles from synthetic fixtures by default.
- Never treat automated tests or redaction as proof that every vulnerability or secret has been detected.
- Document rollback, compromised endpoints, copied shares, and retained plaintext limitations.
