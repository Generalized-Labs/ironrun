## ironrun v0.5.1-rc.1

Local-first encrypted environment workspace for humans and AI coding agents.
Agents receive approved capabilities and redacted output, never reveal APIs.

### Install this release

Supports Linux and macOS on amd64 and arm64. Requires `curl`, `tar`, and
`sha256sum` or `shasum`. The installer uses `cosign` for signature verification;
if it is absent, the installer downloads a pinned verifier and checks its
SHA-256 before running it. Network access is needed for those downloads and
Sigstore verification.

```bash
# Pinned installer for this exact release. The script Sigstore-verifies
# checksums.txt and the tarball, and SHA-256-verifies the tarball
# against checksums.txt — it refuses to install on any failure.
curl -fsSL https://github.com/generalized-labs/ironrun/releases/download/v0.5.1-rc.1/install.sh -o /tmp/install-ironrun.sh
sh /tmp/install-ironrun.sh --version v0.5.1-rc.1

```

### Build from source

With the Go toolchain required by this tag:

```bash
go install github.com/generalized-labs/ironrun/cmd/ironrun@v0.5.1-rc.1
```

A Go source build is separate from the signed release binaries above.
npm and Homebrew availability is managed separately: npm requires
[package bootstrap](https://github.com/generalized-labs/ironrun/blob/v0.5.1-rc.1/docs/NPM_BOOTSTRAP.md),
and the Homebrew cask requires a verified
[tap migration](https://github.com/generalized-labs/ironrun/blob/v0.5.1-rc.1/docs/HOMEBREW_MIGRATION.md).
This GitHub release does not establish that either channel is ready.

Prefer the versioned `install.sh` above over `https://ironrun.dev/install.sh`,
which can follow a newer release instead of pinning this tag. Every release
artifact (`ironrun_<OS>_<arch>.tar.gz`, `checksums.txt`, `install.sh`)
ships with a `<file>.sigstore.json` bundle signed keylessly by the
release workflow; see the
[installation guide](https://github.com/generalized-labs/ironrun/blob/v0.5.1-rc.1/docs/INSTALL.md)
for manual verification and current channel requirements.
