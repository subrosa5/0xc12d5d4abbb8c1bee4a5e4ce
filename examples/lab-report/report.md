# Synthetic recovery lab

Fixture seed: 12

- PASS: all-10-three-of-five-quorums
- PASS: insufficient-shares
- PASS: duplicate-share
- PASS: wrong-password
- PASS: truncated-container
- PASS: modified-authentication-tag
- PASS: trailing-data
- PASS: mixed-vault-shares
- PASS: modified-share
- PASS: process-killed-before-publish
- PASS: existing-output-preserved
- PASS: concurrent-creation-and-observed-nonce-uniqueness
- PASS: restored-immutable-snapshot-readable

## Intentionally broken counter model

This is a separate demonstration, not the vault's nonce generator.

Minimal failure: `encrypt -> restart -> encrypt`

## Replay

From this directory:

```sh
x12 replay report.json --out ../replayed-lab
```

## Limits

- No full-history rollback detection without an independent freshness anchor.
- Replay regenerates synthetic input and experiments, not identical ciphertext.
- Crash coverage is one controlled process-termination boundary, not power loss.
- Counter minimization is a demonstration model, not a discovered vault defect.
