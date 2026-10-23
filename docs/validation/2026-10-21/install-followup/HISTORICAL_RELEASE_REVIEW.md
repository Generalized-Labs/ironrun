# Public release verification — October 21, 2026

Scope: the published historical v0.5.0 release, not the current pull-request code or a future release. No installer script or Ironrun binary was executed, and no credentials were used. Downloads and verifier/cache material are outside the source repository.

The public latest-release API resolves to [v0.5.0](https://github.com/Generalized-Labs/ironrun/releases/tag/v0.5.0), published September 30, 2026. It exposes 16 assets: the installer and checksum manifest with bundles, and four Linux/macOS amd64/arm64 archives, each with an SPDX SBOM and Sigstore bundle. All downloaded assets match the SHA-256 digests returned by the GitHub API.

The installer-pinned official cosign 2.4.3 binary was downloaded and its SHA-256 matched `caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708` before execution. With `SIGSTORE_NO_CACHE=true` to avoid the read-only home cache, real verification passed for all six signed blobs: `checksums.txt`, `install.sh`, and all four archives. Exact certificate identity: `https://github.com/Generalized-Labs/ironrun/.github/workflows/release.yml@refs/tags/v0.5.0`; OIDC issuer: `https://token.actions.githubusercontent.com`. No verification bypass flags were used.

All nine entries in the signed checksum manifest match the downloaded files: installer, four archives, four SBOMs. Each SBOM parses as SPDX 2.3, reports 54 packages, and names Syft 1.42.3 as its producer. The SBOMs are authenticated through the signed checksum manifest, rather than separate SBOM bundles.

Two negative controls fail for the expected reasons: expecting certificate identity v0.5.1 rejects the v0.5.0 certificate, and changing the checksum blob rejects its payload digest. These are real cryptographic-verifier checks, separate from repository fixtures.

Inert `go version -m` inspection reports Go 1.26.5 and source revision `d16e04b09ec8c24e6d6e255caad9209182635af8` for all four published binaries. It also reports `vcs.modified=true`; this evidence does not establish that the published binaries reproduce a clean tag checkout. This older release predates the current repairs/toolchain update, so its valid signatures do not establish current-code launch readiness.

The public v0.5.1 release and tag APIs both return 404. The public registry endpoint `https://registry.npmjs.org/%40generalized-labs%2Fironrun` returns 404 (`Not found`), so there is no publicly visible package tarball/manifest to inspect. This result does not distinguish an absent package from a private one.

Compact evidence: [historical-release-evidence.json](historical-release-evidence.json), including signature results, negative controls, public asset metadata, signed checksum comparisons, SBOM inventory, and inert binary metadata. Downloaded binaries, archives, verifier, and temporary working files remain outside the source repository.
