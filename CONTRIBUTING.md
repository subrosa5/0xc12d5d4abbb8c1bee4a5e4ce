# Contributing

Use Python 3.11+ and uv:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run x12 lab --report /tmp/x12-new-lab-report
```

Use a fresh report directory; outputs are never overwritten.

Cryptographic changes need a threat-model explanation, format impact, malformed-input tests and recovery/failure cases. Reuse maintained library primitives instead of handwritten ciphers or finite-field implementations.

Use synthetic data. Fixed test passwords are fixtures, not production defaults. Never seed cryptographic randomness for repeatability. Key/nonce observations stay in memory in synthetic experiments and must not export key material.

Follow [SECURITY.md](SECURITY.md) for vulnerability reporting. Do not attach real vaults or shares to issues. Distinguish implemented guarantees, planned features and bounded test evidence.
