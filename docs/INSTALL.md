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

Download the installer that shipped with the release you want — this pins
the *script itself*, not just the binary — then run it:

```bash
VERSION=v0.4.1   # pick the release you want
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
   identity (`.../.github/workflows/release.yml@refs/tags/`);
4. SHA-256-verifies the tarball against `checksums.txt`;
5. Sigstore-verifies the tarball bundle itself.

**Any failure aborts the install.** There is no warning-and-continue path.

Flags: `--version vX.Y.Z` (or `IRONRUN_VERSION`), `--dir PATH`
(or `IRONRUN_INSTALL_DIR`), `--help`.

> Prefer this over `curl https://ironrun.dev/install.sh | sh`: ironrun.dev
> currently redirects to the moving `main` branch, so the script you run can
> change with any commit. The versioned asset above is immutable.

## Manual verification

Everything the script does can be done by hand:

```bash
VERSION=v0.4.1
OS=Linux; ARCH=x86_64   # or Darwin / arm64
TARBALL="ironrun_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/generalized-labs/ironrun/releases/download/${VERSION}"

curl -fsSLO "${BASE}/${TARBALL}" "${BASE}/${TARBALL}.sigstore.json" \
          "${BASE}/checksums.txt" "${BASE}/checksums.txt.sigstore.json"

# 1. checksums.txt is signed by the release workflow
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp \
  '^https://github\.com/generalized-labs/ironrun/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# 2. tarball matches checksums.txt
grep " ${TARBALL}\$" checksums.txt | sha256sum -c -

# 3. tarball bundle verifies
cosign verify-blob --bundle "${TARBALL}.sigstore.json" \
  --certificate-identity-regexp \
  '^https://github\.com/generalized-labs/ironrun/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${TARBALL}"
```

## Other install methods

| Method | Command | Verification |
|---|---|---|
| Homebrew tap | `brew tap generalized-labs/tap && brew install ironrun` | url sha256 pin + cosign bundle check in the formula (`Formula/ironrun.rb` is published to `Generalized-Labs/homebrew-tap` by goreleaser on every tag (brews section)) |
| npm / npx | `npx @generalized-labs/ironrun` | postinstall pre-warms the cache; every run re-verifies archive + binary size and SHA-256 against the release manifest (`npm/manifest.json`, built at release time by `npm/scripts/build-manifest.mjs`) |
| Go | `go install github.com/generalized-labs/ironrun/cmd/ironrun@v0.4.1` | Go module checksum DB (`GONOSUMDB` off by default); binary prints its own VCS stamping via `ironrun version -v` |

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
consumed by `install.sh`, `npm/lib/launcher.js`, and `Formula/ironrun.rb` —
change them in all four places or not at all.

## Version stamping

`ironrun version -v` prints the three values stamped at build time via
`-ldflags -X` into `internal/buildinfo`:

| Field | Release builds (goreleaser) | Local builds (`make build`) |
|---|---|---|
| `Version` | `{{.Version}}` — the tag, e.g. `v0.4.1` (displayed without the `v`) | `git describe --tags --always --dirty` |
| `Commit` | `{{.Commit}}` — full commit SHA | `git rev-parse HEAD` |
| `Date` | `{{.Date}}` — RFC 3339 *commit* date | `git log -1 --format=%cI` (commit date) |

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
launcher cache (`~/.cache/ironrun`) is left alone; delete it manually if you
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
