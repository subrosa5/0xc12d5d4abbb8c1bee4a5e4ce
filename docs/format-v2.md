# Streaming container format v2

Implemented in x12 0.2.0. Experimental application composition; external review is pending. Legacy v1 is read unchanged.

## Prefix

Nine-byte magic is ASCII `X12VAULT` plus byte `0x02`. It is followed by a 4-byte big-endian header length (1..4096) and canonical JSON. Canonicalization matches v1: ASCII, sorted keys, no whitespace, duplicate keys rejected. The prefix is the complete magic/length/header sequence.

Exactly these fields are allowed:

| Field | Value |
| --- | --- |
| format | x12-vault |
| version | Integer 2 |
| cipher | AES-256-GCM-STREAM |
| vault_id, recovery_id | 32 lowercase hex characters each |
| threshold, shares | Integers, 2 <= threshold <= shares <= 255 |
| size | Integer, 0..2^40 bytes |
| chunk_size | Integer 1048576 |
| nonce_prefix | 16 lowercase hex characters (8 random bytes) |
| generation | Integer, 1..2^32-1 |
| parent_sha256 | 64 lowercase hex characters; all zeros for initial creation |

Each generation gets a fresh random 32-byte AES key and recovery ID. Rekey preserves vault_id, increments generation, records the previous container hash and fully re-encrypts with a fresh key. V1 migration starts at generation 1. Old copies are not revoked.

## Records

Let N = ceil(size / 1048576). Data record i, 0 <= i < N, has `min(1048576, size-i*1048576)` ciphertext bytes followed by a 16-byte GCM tag. There is no attacker-controlled record length.

- Nonce: decoded nonce_prefix || uint32_be(i).
- AAD: prefix || ASCII D || uint64_be(i) || uint32_be(plaintext_length).
- After data records, a mandatory final 16-byte tag authenticates an empty message.
- Final nonce: nonce_prefix || uint32_be(N).
- Final AAD: prefix || ASCII F || uint64_be(N) || uint32_be(0).

An empty file still has the final tag. EOF is required immediately afterward. Reordering, duplication, substitution, truncation and trailing bytes fail validation. The size bound keeps all nonce counters within range. Key/nonce reuse across immutable generations is avoided by fresh file keys; there is no append or in-place update API.

Every data chunk is verified before reaching a private temporary output. The final output is linked exclusively only after the completion tag and EOF pass. Memory consumption is proportional to chunk size, not file size. A crash can leave temporary authenticated plaintext; secure deletion is not promised.

## Shares and checkpoints

Share envelope v1 remains in use. Its header_sha256 commits to the exact v2 prefix. Each key half is independently shared with PyCryptodome Shamir. Each holder may use a distinct password. Password metadata/AES-GCM protection follow format-v1.md. A receiver can rewrap one approved share without changing its value/index/container binding.

A checkpoint JSON has exactly format=x12-checkpoint, integer version=1, vault_id and sha256 (the whole container's SHA-256). It must be retained through a trusted independent channel. Recovery compares it to the bytes actually consumed before output publication. It is not a global freshness protocol or a signature of an unknown file.

Source changes during create/rekey cause rejection when detected by size/metadata checks or digest comparison. A hostile endpoint/filesystem that can falsify the entire environment is not supported.
