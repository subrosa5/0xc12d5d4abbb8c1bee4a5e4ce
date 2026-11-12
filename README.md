# 0xc12d5d4abbb8c1bee4a5e4ce

**Encrypt a file. Share recovery. Test what happens when things break.**

The repository name looks like a key. The command is **`x12`**.

Experimental **v0.2.0**: native desktop, standalone recovery, streaming containers, per-holder passwords, rekeying, signed device approvals and layered post-quantum delivery. The application protocols have **not received an independent audit**.

[Русский](docs/README.ru.md) · [Recovery](RECOVERY.md) · [v2 format](docs/format-v2.md) · [Device protocol](docs/device-protocol.md) · [Audit package](docs/audit-readiness.md) · [Security](SECURITY.md)

## Start

Download a native archive for your OS from [Releases](https://github.com/subrosa5/0xc12d5d4abbb8c1bee4a5e4ce/releases). It contains `x12`, `x12-recover`, `x12-desktop` and offline documentation. The native binaries include Python and crypto libraries. Builds are not developer-ID signed/notarized; OS approval may be required.

Or use Python 3.11+ with uv:

```sh
git clone https://github.com/subrosa5/0xc12d5d4abbb8c1bee4a5e4ce.git
cd 0xc12d5d4abbb8c1bee4a5e4ce
uv sync --locked
uv run x12 lab --report ./lab-report
uv run x12 desktop
```

The desktop interface needs a Python distribution with working Tcl/Tk. Native desktop builds include it. On Linux, a graphical session is required. Vault operations do not use a network service.

## Create and recover

```sh
uv run x12 create ./document.txt --out ./my-vault --threshold 3 --shares 5 --per-holder
```

Each holder gets an independently password-protected share. Distribute `share-*.x12share` files separately and keep their passwords available independently. Retain `vault.x12`; `COMPLETE` is written last. Leaving all shares and passwords together defeats distributed custody.

```sh
uv run x12 recover ./my-vault/vault.x12 \
  --share ./holder-1.x12share \
  --share ./holder-3.x12share \
  --share ./holder-5.x12share \
  --per-holder --out ./restored.txt
```

`x12-recover` accepts the same vault/share/output arguments without the `recover` subcommand. It reads both legacy v1 and current v2 files. No project checkout, Python installation or internet is needed by the native recovery binary.

Automation can use repeated `--holder-password-file` during creation and repeated `--share-password-file` during recovery, in matching share order. `--password-file` retains the common-password mode. Password-file handling removes one final LF and its preceding CR; interactive strings use UTF-8 without normalization. Passwords need 12–1024 bytes; use strong passwords.

## Replace holders

```sh
uv run x12 rekey ./my-vault/vault.x12 \
  --share ./holder-1.x12share --share ./holder-3.x12share --share ./holder-5.x12share \
  --per-holder --out ./next-generation --threshold 2 --shares 3 --new-per-holder
```

The new generation has a fresh file key and new shares. Old shares do not unlock the new generation. **Old copies remain readable with their old keys/shares.** No plaintext intermediate file is used for v2 rekeying.

## Retain an exact-version checkpoint

```sh
uv run x12 checkpoint ./next-generation/vault.x12 --out ./latest.checkpoint
```

Keep this file independently from the vault. Supply it as `--checkpoint ./latest.checkpoint` on recovery/rekeying to reject a different version. A checkpoint is an exact-byte commitment; it does not independently establish which version is latest or authenticate an untrusted file. Replacing both the vault and checkpoint with old valid copies is outside this protection.

## Device approvals

```sh
uv run x12 identity --out ./my-device
uv run x12 fingerprint ./peer-device/identity.public.json
```

Verify full fingerprints with the other person through an independent channel. Requests and responses are files, so they can be carried over a channel of your choice. Release requires explicit `--confirm`. Both ML-DSA-65 and Ed25519 signatures are checked. Share values are encrypted in nested library HPKE layers using ML-KEM-768 and X25519. The receiver rewraps the approved share under a new local password; the holder's password is never handed over.

See the complete [request → approve → receive workflow](docs/device-protocol.md). Approval authorizes release of a share. It does not enforce fresh consent for every later read. Retain the requester ledger independently; restoring an old ledger can undo local replay protection.

## Crash lab and reproducible errors

```sh
uv run x12 lab --report ./lab-report
uv run x12 replay ./lab-report/report.json --out ./replayed-lab
uv run x12 reduce examples/failure-trace.json --out ./minimal-error
uv run x12 replay-trace ./minimal-error/trace.json
```

The lab uses synthetic data, checks all ten 3-of-5 quorums, malformed inputs, concurrent encryption, immutable snapshots, five real process-termination boundaries and v2 rekey/checkpoint recovery. Replay regenerates input and experiments, with fresh cryptographic randomness.

The reducer deletes operations while preserving an actual recovery error from the streaming implementation. Expected rejection of a corrupted file is not a security vulnerability. The separate broken-counter demonstration is explicitly labeled. Reports never execute JSON-supplied commands or read user vaults.

## Implementation

| Component | Implemented behavior |
| --- | --- |
| File encryption | Fresh AES-256 key, authenticated 1 MiB chunks and final marker, bounded memory, up to 1 TiB |
| Key recovery | Two independent PyCryptodome Shamir schemes, 2–255 holders, per-holder scrypt/AES-GCM envelopes |
| Storage | Exclusive publication, existing destinations preserved, private POSIX files |
| Generations | Streaming fresh-key re-encryption and changed holder sets; v1 import |
| Desktop | Create, recover, replace holders and run the synthetic lab |
| Device handoff | Fingerprint pinning, dual signatures, nested ML-KEM/X25519 HPKE, expiry, local one-use ledger |
| Distribution | Python wheel/source and OS-native offline executables |

PyCryptodome supplies all cipher, sharing, KDF, KEM and signature implementations. The container and device protocol compositions are experimental application code. [Third-party notices](THIRD_PARTY.md).

## Security boundaries

Creating/recovering devices see the full key and plaintext. This is Shamir-based key recovery, not a protocol that keeps the file key permanently distributed. Python cannot reliably zeroize secret buffers. Individual authenticated chunks may reach a private temporary file before the final marker is checked; the final path is published only after complete verification. Abrupt termination can leave that temporary plaintext. File size and quorum metadata are public.

Tests are bounded evidence, not an audit or proof. Physical power-loss durability, malicious endpoints, global freshness, remote erasure, automatic revocation of old copies and forward secrecy of stored device capsules are not provided. See [SECURITY.md](SECURITY.md) and [the roadmap](docs/roadmap.md).

## Development

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv sync --locked --group build
uv run --group build python tools/build_native.py
```

[Contributing](CONTRIBUTING.md). Test on synthetic files until independent review. Related work includes [rememory](https://github.com/eljojo/rememory), [Threshold Vault](https://github.com/threshold-vault/shards-core), [CRYLOGGER](https://github.com/lucapiccolboni/crylogger), [Wycheproof](https://github.com/C2SP/wycheproof) and [ReproZip](https://github.com/ViDA-NYU/reprozip).

MIT. See [LICENSE](LICENSE).
