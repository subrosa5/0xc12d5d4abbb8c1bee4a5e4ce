# 0xc12d5d4abbb8c1bee4a5e4ce

**A local-first threshold file vault with reproducible recovery testing.**

The name looks like a key. It is only a name.

Status: design scaffold. There is no vault implementation or installable release yet.

[Русский](docs/README.ru.md) · [Architecture](docs/architecture.md) · [Roadmap](docs/roadmap.md) · [Security](SECURITY.md)

## The idea

Encrypt a file, distribute recovery shares to people you trust, and recover it with a quorum — for example, any three of five shares. Test recovery before you need it.

Three parts form one project:

| Part | Planned purpose |
| --- | --- |
| Vault | Authenticated file encryption and threshold key recovery |
| Crash lab | Controlled failure experiments against synthetic vaults |
| Reproducer | Minimal, replayable bug reports with synthetic fixtures |

The initial interface will focus on creating a vault, recovering a vault, and testing recovery. Post-quantum transport and cross-device approvals are later research directions, not current features.

## Planned first release

- A documented, versioned offline container format.
- A fresh random file key and established authenticated encryption.
- Threshold recovery using an established Shamir implementation.
- A separate offline recovery command.
- Tests for interrupted writes, corrupted containers, missing shares, and state restoration.
- Reproducible failure artifacts generated from synthetic data.

## Trust boundaries

In the first design, the creating device holds the full file key. During recovery, a quorum of shares reconstructs it on the receiving device. A recipient can retain the key or plaintext. This is threshold recovery, not an enforceable requirement for fresh approval on every read.

An offline vault cannot reliably detect replacement of its entire history with an older valid copy without an independent freshness anchor. Failure tests exercise specified scenarios; passing them does not prove complete security.

## Development

Implementation has not started. The first milestone is a threat model and container specification, followed by a CLI prototype and a failure-testing harness. See the [roadmap](docs/roadmap.md).

Contributions should use existing cryptographic primitives and libraries, document assumptions, and include meaningful recovery or failure cases. Do not attach real keys, recovery shares, or private files to issues.

## Related work

- [rememory](https://github.com/eljojo/rememory): a digital safe with multiple keys held by trusted people.
- [Threshold Vault](https://github.com/threshold-vault/shards-core): secret sharing and offline recovery.
- [CRYLOGGER](https://github.com/lucapiccolboni/crylogger): dynamic cryptographic misuse detection.
- [Wycheproof](https://github.com/C2SP/wycheproof): cryptographic test vectors.
- [ReproZip](https://github.com/ViDA-NYU/reprozip): reproducible execution bundles.

The proposed focus is integrating recovery with controlled failure experiments and reproducible diagnostics. No claim of unique invention or audited security is made.

## License

MIT. See [LICENSE](LICENSE).
