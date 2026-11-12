# Offline recovery kit

Keep the native `x12-recover` binary for your OS, a vault, enough protected shares, their passwords, and this document. Native binaries bundle their runtime and PyCryptodome. No account, project checkout or online service is involved during recovery.

The v0.2 recovery binary reads legacy v1 and streaming v2. Choose an archive for your OS and architecture. Platform binaries are built and smoke-tested on that OS; they are not interchangeable across OSes.

```sh
./x12-recover vault.x12 \
  --share holder-1.x12share --share holder-3.x12share --share holder-5.x12share \
  --out restored-file
```

You will be prompted for each supplied share's password. With a common password file, use `--password-file /private/password-file`; for independent files, repeat `--share-password-file` in the same order as the shares. Password files are not part of the share and must remain available independently.

For an independently retained exact-version checkpoint, add `--checkpoint /independent/latest.checkpoint`.

Existing output files are never overwritten. Use a new destination. The final path appears only after authentication of all chunks and the completion marker. An interrupted operation can leave a private `.x12-*` temporary file containing authenticated plaintext chunks. Such remnants are not securely erased by the tool.

If a supplied share is invalid, the tool rejects the set. Choose a different valid quorum; it does not automatically search combinations. Duplicate share indices and mixed generations are rejected. Losing enough shares or passwords cannot be repaired by the software.

Use `x12-desktop` for a graphical recovery flow. The recovery engine is the same.

This experimental kit is not independently audited. Verify recovery on synthetic/test copies before relying on it. Retain verified binaries and checksums for long-term offline access; downloading a future executable is a supply-chain trust decision.
