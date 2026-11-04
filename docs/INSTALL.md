# Installing ironrun

ironrun ships as a single static Go binary. Every release publishes
prebuilt binaries for Linux and macOS (amd64 + arm64). Windows is not
shipped for the OSS launch (see docs/windows.md). Each release artifact is
covered by **two independent integrity proofs**:

1. `checksums.txt` — SHA-256 of every artifact, itself Sigstore-signed by
   the release workflow (`checksums.txt.sigstore.json`);
2. a per-artifact Sigstore bundle (`<artifact>.sigstore.json`), signed
   keylessly by the ironrun release workflow via GitHub OIDC.

ironrun collects no telemetry; see [telemetry.md](telemetry.md).

## Recommended install (pinned, verified)

Choose an already-published tag from the
[release list](https://github.com/generalized-labs/ironrun/releases). Download
the installer attached to that exact release, then run it with the same tag.
An RC must be selected explicitly; it is not selected by the latest-stable URL.

Requires `curl`, `tar`, and `sha256sum` or `shasum`, plus the standard Unix
utilities used by the script. Signature verification needs `cosign`: the
installer uses an existing copy or downloads its pinned verifier after checking
the verifier's SHA-256. Network access is required for the release/verifier
downloads and Sigstore verification. Do not bypass verification if a dependency
or network request fails.

```bash
VERSION=vX.Y.Z   # pick the release you want
curl -fsSL "https://github.com/generalized-labs/ironrun/releases/download/${VERSION}/install.sh" \
  -o /tmp/install-ironrun.sh
sh /tmp/install-ironrun.sh --version "$VERSION"
```

Before touching your system the script:

1. downloads the tarball, `checksums.txt`, and both `.sigstore.json` bundles;
2. provisions `cosign` — your system copy if present, otherwise the pinned
   `sigstore/cosign v2.4.3` release binary, whose SHA-256 is hardcoded in the
   script and checked before it is executed;
3. Sigstore-verifies `checksums.txt` against the release workflow's OIDC
   identity bound to the requested tag (`.../.github/workflows/release.yml@refs/tags/vX.Y.Z`);
4. SHA-256-verifies the tarball against `checksums.txt`;
5. Sigstore-verifies the tarball bundle itself.

**Any failure aborts the install.** There is no warning-and-continue path.

Flags: `--version vX.Y.Z` (or `IRONRUN_VERSION`), `--dir PATH`
(or `IRONRUN_INSTALL_DIR`), `--help`.

> Prefer the versioned URL above over `curl https://ironrun.dev/install.sh | sh`:
> the website URL can follow a newer release instead of selecting your intended
> tag. A versioned URL fixes release selection; it is not an independent
> signature check of the installer script before you execute it.

## Manual verification

To verify the downloaded release files manually, first install a compatible
`cosign` from its [official distribution](https://docs.sigstore.dev/cosign/system_config/installation/).
The commands below also require `curl`, `sha256sum`, `grep`, and `sed`. On macOS,
use `shasum -a 256 -c -` in place of `sha256sum -c -`.

```bash
VERSION=vX.Y.Z
OS=Linux; ARCH=x86_64   # or Darwin / arm64
TARBALL="ironrun_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/generalized-labs/ironrun/releases/download/${VERSION}"
# VERSION must be a release tag; escape dots and bind the complete identity.
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || exit 1
TAG_PATTERN=$(printf '%s' "$VERSION" | sed 's/\./\\./g')
IDENTITY="^https://github\.com/[Gg]eneralized-[Ll]abs/ironrun/\.github/workflows/release\.yml@refs/tags/${TAG_PATTERN}\$"

curl -fsSLO "${BASE}/${TARBALL}" "${BASE}/${TARBALL}.sigstore.json" \
          "${BASE}/checksums.txt" "${BASE}/checksums.txt.sigstore.json"

# 1. checksums.txt is signed by the release workflow
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp \
  "$IDENTITY" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# 2. tarball matches checksums.txt
grep " ${TARBALL}\$" checksums.txt | sha256sum -c -

# 3. tarball bundle verifies
cosign verify-blob --bundle "${TARBALL}.sigstore.json" \
  --certificate-identity-regexp \
  "$IDENTITY" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${TARBALL}"
```

## Other distribution channels

Publishing GitHub assets does not make npm or a Homebrew cask available.
At the October 30, 2026 review, the npm package had not been bootstrapped and
the live tap still carried the v0.5.0 formula. Use the pinned installer above
for signed binary installation; check each channel before advertising it.

| Method | Availability and version selection | Verification |
|---|---|---|
| Homebrew tap | The new cask is pending the reviewed [migration and native install/upgrade checks](HOMEBREW_MIGRATION.md). A generated draft tap PR is not a live installation channel; prereleases do not update the tap | Casks pin archive URLs and SHA-256. Homebrew does not verify Sigstore bundles; use the installer for that |
| npm / npx | Requires [first-package bootstrap and trusted-publisher setup](NPM_BOOTSTRAP.md). Only after the exact version is published, select it explicitly with `npx @generalized-labs/ironrun@X.Y.Z` (or the full `X.Y.Z-rc.N` version for an RC) | Every run verifies archive/binary size and SHA-256 against the prepared release manifest; this does not replace the release-input signature checks |
| Go | With the tag's required Go toolchain, `go install github.com/generalized-labs/ironrun/cmd/ironrun@vX.Y.Z`; use the full RC tag when applicable | Compiles source through the Go module system. This is not installation of the signed release binary; `ironrun version -v` reports the module version and available build metadata |

For npm proxy opt-in, read-only cache behavior, and current package availability,
see [npm runtime support](NPM_RUNTIME_SUPPORT.md).

## Artifact naming

| Artifact | Name template | Example |
|---|---|---|
| Release tarball (Linux/macOS) | `ironrun_<OS>_<arch>.tar.gz` | `ironrun_Linux_x86_64.tar.gz` |
| Checksums | `checksums.txt` | `<sha256>  <filename>` lines |
| Sigstore bundle | `<artifact>.sigstore.json` | `ironrun_Linux_x86_64.tar.gz.sigstore.json` |
| Installer (release asset) | `install.sh` | also listed in `checksums.txt` |
| SBOM | `<artifact>.sbom.json` (spdx) | per archive |

`<OS>` is `Linux` or `Darwin`; `<arch>` is `x86_64` or `arm64`.
These names are produced by `.goreleaser.yml` (`archives.name_template`) and
consumed by `install.sh`, `npm/lib/launcher.js`, and the generated Homebrew
cask. The legacy `Formula/ironrun.rb` remains historical packaging until the
tap migration. Update and verify every consumer when changing archive names.

## Version stamping

`ironrun version -v` prints the three values stamped at build time via
`-ldflags -X` into `internal/buildinfo`:

| Field | Release builds (goreleaser) | Local builds (`make build`) |
|---|---|---|
| `Version` | `{{.Version}}` — the tag, e.g. `v0.4.1` (displayed without the `v`) | `git describe --tags --always --dirty` |
| `Commit` | `{{.Commit}}` — full commit SHA | `git rev-parse HEAD` |
| `Date` | `{{.CommitDate}}` — RFC 3339 *commit* date | `git log -1 --format=%cI` (commit date) |

The date is always the commit date, never wall-clock time — this is what
makes the stamping reproducible.

## Reproducible builds

Release binaries are built with:

```
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w \
    -X github.com/generalized-labs/ironrun/internal/buildinfo.Version=<tag> \
    -X github.com/generalized-labs/ironrun/internal/buildinfo.Commit=<sha> \
    -X github.com/generalized-labs/ironrun/internal/buildinfo.Date=<rfc3339>" \
  -o ironrun ./cmd/ironrun
```

Why this is reproducible:

- `-trimpath` removes local filesystem paths from the binary;
- `-s -w` strips the symbol table and DWARF debug info;
- `CGO_ENABLED=0` removes libc/toolchain variance;
- no wall-clock input — `Date` is the commit date;
- `go.sum` pins every module dependency.

Verify it yourself:

```bash
make verify-reproducible   # builds this tree twice, requires identical SHA-256
```

Caveat: reproducibility holds for a fixed Go toolchain version (recorded in
`go.mod`) and a fixed commit. Different Go patch releases may produce
different bytes; the release workflow pins the toolchain via
`go-version-file: go.mod`.

## Uninstall

The installer removes the binary; config and secret data are kept unless you
explicitly purge them:

```bash
# remove the binary (checks /usr/local/bin, ~/.local/bin, and PATH)
sh /tmp/install-ironrun.sh --uninstall

# also delete ~/.ironrun (project registry, encrypted secret stores)
# --purge asks for typed confirmation; add --yes for non-interactive use
sh /tmp/install-ironrun.sh --uninstall --purge --yes
```

`--purge` prints a recovery warning first — there is no undo. The npm
launcher cache (`~/.cache/ironrun` on Linux, `~/Library/Caches/ironrun` on macOS) is left alone; delete it manually if you
also used `npx @generalized-labs/ironrun`.

## Troubleshooting

- **"no checksum entry for …"** — the release is incomplete; do not install
  from it. Report it as a release bug.
- **Sigstore verification failed** — do not bypass it. Check your clock
  (certificate validity is time-sensitive) and that you are installing an
  actual GitHub release asset, not a re-hosted copy.
- **cosign not found and no network** — the script cannot verify signatures
  offline on first run; use the manual `sha256sum -c` check against a
  `checksums.txt` you obtained and verified separately.
- **Windows** — unsupported for the OSS launch (see docs/windows.md); no
  Windows artifacts are published and `install.sh` refuses non-Linux/macOS
  systems.
