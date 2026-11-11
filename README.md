# 0xc12d5d4abbb8c1bee4a5e4ce

**Encrypt a file. Split recovery across people. Test that recovery works.**

The name looks like a key. It is only a name. The command is **`x12`**.

Experimental CLI **v0.1.0**. Implemented and tested, but not externally audited. Use test data while the protocol is under development.

[Русский](docs/README.ru.md) · [Format](docs/format-v1.md) · [Architecture](docs/architecture.md) · [Roadmap](docs/roadmap.md) · [Security](SECURITY.md)

## Try the crash lab

Python 3.11+ and [uv](https://docs.astral.sh/uv/) are required. Initial development targets macOS and Linux.

```sh
git clone https://github.com/subrosa5/0xc12d5d4abbb8c1bee4a5e4ce.git
cd 0xc12d5d4abbb8c1bee4a5e4ce
uv sync --locked
uv run x12 lab --report ./lab-report
```

This runs isolated experiments against synthetic files: all ten 3-of-5 recovery quorums, missing/duplicate/mixed/modified shares, wrong passwords, damaged containers, concurrent encryption, restored snapshots, and a real process killed before file publication. It writes readable and JSON reports.

```sh
uv run x12 replay ./lab-report/report.json --out ./replayed-lab
```

Replay regenerates synthetic input and reruns experiments. Keys and ciphertext are intentionally fresh. Reports are data, never executable instructions.

The report also reduces an intentionally broken nonce-counter model to `encrypt -> restart -> encrypt`. That model is separate from the vault implementation and is explicitly identified as such.

## Create a vault

```sh
uv run x12 create ./document.txt --out ./my-vault --threshold 3 --shares 5
```

You will be prompted for a recovery-share password of at least 12 UTF-8 bytes and its confirmation. The new private directory contains:

```text
my-vault/
  vault.x12
  share-001.x12share
  share-002.x12share
  share-003.x12share
  share-004.x12share
  share-005.x12share
  COMPLETE
```

Distribute shares to separate holders and keep the recovery password available independently. **Leaving every share together defeats distributed custody.** This version uses one common password for all shares, with independent salts and nonces. A quorum AND that password are required. Losing the password loses access even if enough shares survive.

## Recover offline

```sh
uv run x12 recover ./my-vault/vault.x12 \
  --share ./my-vault/share-001.x12share \
  --share ./my-vault/share-003.x12share \
  --share ./my-vault/share-005.x12share \
  --out ./restored.txt
```

The complete file is authenticated before any plaintext output is written. Existing destinations are never overwritten. Supply `--password-file /path/to/private-file` for automation; no password argument or environment variable is needed. The reader removes one final LF and an immediately preceding CR from password files.

```sh
uv run x12 inspect ./my-vault/vault.x12
```

`inspect` shows **unauthenticated public metadata**, not a security verdict.

## What is implemented

| Part | v0.1.0 |
| --- | --- |
| Vault | AES-256-GCM, fresh per-file key, authenticated versioned header, files up to 64 MiB |
| Recovery | Configurable 2–255 holders, Shamir key sharing, password-protected share envelopes |
| Storage | Private files/directories on POSIX, exclusive output publication, no overwrite |
| Crash lab | Synthetic adversarial inputs, concurrency observation, real interruption boundary |
| Reproducer | Seeded synthetic replay and deletion reduction for a demonstration counter model |

AES-GCM, scrypt and Shamir come from [PyCryptodome](https://www.pycryptodome.org/). There are no custom cipher implementations. The container protocol and composition are experimental application code.

## Limits that matter

- Recovery reconstructs the full file key on the receiving device. Recipients can retain keys or plaintext; there is no enforceable fresh approval on every read.
- Size, quorum parameters and random identifiers are public. File names are not stored in the container.
- All supplied shares must validate; automatic exclusion of malicious shares is not implemented.
- A password holder can forge share envelopes; they are not participant signatures. File authentication is the final check of reconstructed content.
- Old valid containers and old shares remain usable. Full-history rollback detection needs an independent freshness anchor.
- Files are processed in memory. Python cannot reliably zeroize secrets. An interrupted write can leave a private `.x12-*` temporary file; recovery temporary files contain authenticated plaintext.
- `COMPLETE` marks a fully written bundle. Failed creation can leave an incomplete directory. The source is never deleted.
- Tests provide bounded evidence, not a security proof. Hardware power-loss behavior and cross-platform ACLs are not established by the crash experiment.
- Post-quantum delivery, device approvals, a GUI, rekeying and external-application instrumentation are not implemented.

## Development

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Once dependencies are installed, vault operations and the lab need no account, cloud service, telemetry or network access.

## Related work

[rememory](https://github.com/eljojo/rememory), [Threshold Vault](https://github.com/threshold-vault/shards-core), [CRYLOGGER](https://github.com/lucapiccolboni/crylogger), [Wycheproof](https://github.com/C2SP/wycheproof), and [ReproZip](https://github.com/ViDA-NYU/reprozip) address related recovery, testing and reproducibility problems. No claim of unique invention is made.

## License

MIT. See [LICENSE](LICENSE).
