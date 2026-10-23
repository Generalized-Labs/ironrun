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

## Proxies and cache permissions

The native download uses Node's `fetch`, separately from npm registry settings.
On Node 22.21+ or Node 24+, enable its proxy support before starting npx:

```sh
NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://proxy.example:8080 npx @generalized-labs/ironrun@latest
```

`NO_PROXY` selects direct connections. For an organization's TLS authority, set
`NODE_EXTRA_CA_CERTS` to its CA file before starting Node. Node 20 has no built-in
environment-proxy opt-in; use a newer runtime or the verified native installer.

A verified warm cache runs offline with read-only directory permissions. Cold
or corrupt caches require write access and otherwise refuse execution. Cache
locations are `~/.cache/ironrun/v<version>` on Linux and
`~/Library/Caches/ironrun/v<version>` on macOS. See the
[runtime support details](https://github.com/Generalized-Labs/ironrun/blob/main/docs/NPM_RUNTIME_SUPPORT.md)
for the tested scope and alternatives.
