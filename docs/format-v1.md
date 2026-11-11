# Experimental format v1

Implemented by `x12-vault` 0.1.0. This application protocol is not an independently reviewed cryptographic standard. Incompatible changes require a new version.

## Container

```text
magic          9 bytes: ASCII X12VAULT followed by byte 0x01
header_length  4 bytes: unsigned big-endian integer, 1..4096
header         header_length bytes of canonical JSON
nonce          12 bytes
ciphertext     exactly header.size bytes, 0..67108864
tag            16 bytes
```

Canonical JSON uses ASCII output, lexicographically sorted keys, no whitespace, comma separators and colon key/value separators. Duplicate keys are invalid. `magic || header_length || header` is AES-GCM associated data. Truncation and extra bytes are rejected. The AES key is 32 bytes; the tag is 16 bytes.

Header fields are exact, with no additional fields:

| Field | Value |
| --- | --- |
| `format` | `x12-vault` |
| `version` | integer `1`, not a boolean |
| `cipher` | `AES-256-GCM` |
| `vault_id` | 16 random bytes as 32 lowercase hex characters |
| `recovery_id` | independent 16 random bytes as lowercase hex |
| `threshold` | integer, 2..shares |
| `shares` | integer, 2..255 |
| `size` | plaintext bytes, 0..67108864 |

Each creation generates a fresh file key, identifiers and nonce. There is no append or update under an existing key. Parsing public metadata alone is not authentication.

## Secret sharing

Split the AES key into `key[0:16]` and `key[16:32]`. Call PyCryptodome `Shamir.split(threshold, shares, half, ssss=False)` independently for each half. Each participant receives both 16-byte values at the same index. Combine halves independently with `Shamir.combine(..., ssss=False)` and concatenate in order.

This composes two GF(2^128) schemes; it is not a custom GF(2^256) implementation. It is not compatible with SLIP-39 or arbitrary secret-sharing formats.

## Protected shares

Maximum share file length is 8192 bytes. The outer JSON object has exactly `metadata`, `ciphertext` and `tag`. Duplicates are rejected. The encrypted payload is `left_share || right_share`, exactly 32 bytes.

Metadata fields are exact:

| Field | Value |
| --- | --- |
| `format` | `x12-share` |
| `version` | integer `1` |
| `index` | integer, 1..shares |
| `vault_id`, `recovery_id`, `threshold`, `shares` | Match the container header with exact types |
| `header_sha256` | Lowercase SHA-256 hex digest of the complete container prefix |
| `kdf` | `scrypt-N32768-r8-p1` |
| `salt` | 16 independent random bytes, canonical padded standard Base64 |
| `nonce` | 12 independent random bytes, canonical padded standard Base64 |

`wrapping_key = scrypt(password_bytes, salt, key_len=32, N=32768, r=8, p=1)`.
Share encryption uses AES-256-GCM with `canonical(metadata)` as AAD. Outer ciphertext and tag use canonical padded standard Base64 and decode to 32 and 16 bytes. Untrusted files cannot alter KDF resource parameters. Each derivation needs roughly 32 MiB plus overhead.

Interactive passwords use UTF-8 without normalization. Password files supply raw bytes after removal of one final LF and an immediately preceding CR. Length is 12..1024 bytes; this minimum is not an entropy guarantee. All shares use the same password with independent salts/nonces. There are no participant signatures.

Reports contain no real key, share or plaintext. Containers and shares embed no commands or paths. Full-history freshness and old-copy revocation are outside this format.
