# npm launcher: proxies and cache permissions

The launcher supports Linux/macOS on amd64/arm64. It downloads the native
archive matching its package version, verifies archive and binary hashes, and
rechecks the cached binary before every execution. This page describes the
network and filesystem behavior exercised during launch validation.

## HTTP proxies

The native-archive download uses Node's global `fetch`. npm's registry proxy
settings do not configure that separate request. `HTTP_PROXY`/`HTTPS_PROXY`
alone also do not enable Node's built-in proxy handling by default.

| Node runtime | Native-archive proxy handling |
| --- | --- |
| 20.x | Built-in environment-proxy opt-in is unavailable; use a newer Node runtime or verified native installation |
| 22.x, version 22.21 or later | Start Node with `NODE_USE_ENV_PROXY=1` and set the proxy variables |
| 24.x | Start Node with `NODE_USE_ENV_PROXY=1` and set the proxy variables |

For supported modern Node versions:

```sh
NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://proxy.example:8080 npx @generalized-labs/ironrun@latest
```

Set `NO_PROXY` to the hosts that should connect directly. A match for GitHub
bypasses the proxy for that host. If an organization uses its own TLS authority,
set `NODE_EXTRA_CA_CERTS=/path/to/company-ca.pem` before starting Node. TLS
certificate verification remains enabled.

The alternative `--use-env-proxy` flag requires Node 22.21+ or 24.5+. The
environment option is available from Node 22.21 and 24.0. See the official
[Node 22](https://nodejs.org/docs/latest-v22.x/api/cli.html#node_use_env_proxy1)
and [Node 24](https://nodejs.org/docs/latest-v24.x/api/cli.html#node_use_env_proxy1)
CLI documentation. These instructions describe the tested Node 20/22/24 lines;
they do not establish behavior for every other Node release.

Validation used a loopback CONNECT proxy, synthetic trusted TLS authority,
GitHub-style redirect, and the actual launcher/hash/extraction/child path.
An external-DNS guard prevented real network fallback. Cases include proxy
success, missing opt-in, `NO_PROXY`, failed proxy, untrusted certificate,
tampered archive, and warm-cache use with the proxy unavailable. No fetch
replacement or disabled TLS verification was used in that transport fixture.
These transport checks ran on Linux amd64; they do not establish macOS proxy
behavior or support for every corporate proxy authentication scheme.

## Read-only cache permissions

The current cache locations are:

- Linux: `~/.cache/ironrun/v<package-version>/`
- macOS: `~/Library/Caches/ironrun/v<package-version>/`

A verified warm binary runs offline when its cache directory has read-only
permissions. A cold or corrupt cache needs write access to lock/download/repair;
otherwise the launcher refuses execution. It does not execute the corrupt
cached file. Tests use real directory permissions and subprocesses under a
non-root user; they do not establish behavior on every read-only filesystem
mount. There is currently no custom cache-directory setting in the launcher.

For a read-only home without a verified warm cache, install the verified native
binary into a writable location with the shell installer's `--dir` option, or
use `go install` with a writable `GOBIN`. If cosign cannot write its trust-data
cache under the home directory, `SIGSTORE_NO_CACHE=true` avoids that cache while
retaining signature verification. That setting was used for real verification
of the historical public v0.5.0 assets during this review.

## Public availability

As checked October 21, 2026, GitHub's latest public release is v0.5.0; v0.5.1
release/tag endpoints and the public npm package endpoint return 404. A 404 does
not distinguish an absent package from a private one. The fixes in PR #16 are
source changes, not a published release. Before the first public npm package,
follow [NPM_BOOTSTRAP.md](NPM_BOOTSTRAP.md); the manifest must be generated from
matching real release archives. The npx example above applies after publication.
