# Release installation copy correction

The isolated branch `launch/release-usability-20261030` starts from merged
commit `6e03c06aebff3040563a3d8d147875824af9d366`. Only `.goreleaser.yml`
and `docs/INSTALL.md` change. Go source, release triggers, publication ordering,
credentials, npm bootstrap and the live Homebrew tap are untouched.

The release header now offers an exact-tag installer and exact-tag Go source
build. It explains the verifier and network prerequisites, distinguishes source
builds from signed binaries, and links to the channel prerequisites instead of
advertising an unavailable npm package or unverified cask. The installation
guide describes explicit RC selection, existing/pinned `cosign`, manual verifier
setup, and conditional channel availability. It no longer claims the website
installer follows moving main or that a versioned script URL is itself a
signature check.

## Verification

- The actual pinned GoReleaser 2.18.2 `check` exits zero on the edited config.
  Raw stdout/stderr and tool version are retained.
- `git diff --check` passes. `source.diff` and `source-identities.json` identify
  the reviewed changes; no Go source is edited.
- Two actual GoReleaser diagnostic releases use the unchanged release stanza,
  explicit `v0.5.1-rc.1` / `v0.5.1` tag context, a skipped build and skipped
  publication/signing/packaging. They exit zero and retain matching tag/version
  metadata. They do not create Git tags. The minimal diagnostic configs and
  generated metadata are retained separately from the repository's full config.
- With publication skipped, GoReleaser does **not** emit its release header.
  The exact header extracted from the checked YAML is therefore also rendered
  by Go 1.26.10's standard `text/template`, using the identical `.Tag` field.
  This header contains no GoReleaser-specific template functions. The source
  driver is retained as `render_header.go.txt`, with both rendered outputs and
  URL/command assertions in `render-results.json`.
- Both outputs contain the matching tagged installer URL, `--version` argument
  and Go source path. Neither contains an unconditional cask/npx command or
  unexpanded tag. Both explain `cosign` and channel prerequisites.

These checks establish configuration and copy rendering, not the existence of
either proposed tag, published signatures, a successful native installation,
npm availability, or Homebrew migration. No tag, release binary/archive,
signature, registry package, tap update or deployment was created. Diagnostic
metadata files are retained. Actual UTC timestamps may fall on October 31 while
the task's user-facing date/session label is October 30 in America/New_York.

The artifact manifest hashes retained files and excludes itself.
