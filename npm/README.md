# @generalized-labs/ironrun

Verified launcher for the native Ironrun Go binary.

```bash
npx @generalized-labs/ironrun@latest
```

The package contains no vault, policy, redaction, or execution logic. On
install, a `postinstall` script pre-warms the cache by downloading the
GitHub release matching this package's version for your platform
(`npm/manifest.json` pins each archive's size and SHA-256, plus the
extracted binary's size and SHA-256). The postinstall is fail-open: if the
network is unavailable it only warns, and the binary is fetched on first
run instead.

Every run re-verifies the cached binary (size + SHA-256) before executing
anything, and the launcher connects its stdio and signals directly to the
terminal.

ironrun collects no telemetry; see `docs/telemetry.md` in the main repo.
