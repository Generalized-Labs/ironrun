# @generalized-labs/ironrun

Verified launcher for the native Ironrun Go binary.

```bash
npx @generalized-labs/ironrun@latest
```

The package has no lifecycle scripts and contains no vault, policy, redaction,
or execution logic. It downloads only the matching GitHub release, verifies the
embedded archive and binary sizes and SHA-256 hashes, caches the verified
binary, and connects its stdio and signals directly to the terminal.
