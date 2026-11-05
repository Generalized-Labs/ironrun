# Native storage and release-readiness follow-up

[PR #16](https://github.com/Generalized-Labs/ironrun/pull/16) merged as
`6e03c06aebff3040563a3d8d147875824af9d366`. These records preserve the checks
that preceded the merge, the later real Linux Secret Service probe, and the
release-instruction correction. The original measurements retain their exact
source identities; copying them here does not rerun or relabel them.

| Archive | Evidence and limits |
| --- | --- |
| [verification](verification/README.md) | Uncached Go race suite, vet, Staticcheck, build, CLI smoke, 11 release regressions and 19 Node 24 tests pass on `07eb2c4`; all 182 runtime inputs match the merged implementation. The captured current-head GitHub checks include successful Linux/macOS, security, Node 20/22/24, CodeQL, fuzz and dogfood checks; optional Macroscope was skipped |
| [native-linux](native-linux/README.md) | Real GNOME Keyring 48.0/libsecret 0.21.7 over a new isolated DBus session: native root-key save/reopen, encrypted vault, MCP approval, authenticated loopback child, filtered output, strict attempted-dial denial, revoke/deny and persistence across native-daemon restart. All 182 runtime inputs match `6e03c06`. This is headless Debian with scripted CLI approval, not desktop unlock, a real host/model or human usability |
| [release-copy](release-copy/README.md) | GoReleaser configuration and exact-tag RC/stable instruction rendering checks. Installer/source commands select their exact tag; unavailable npm/cask channels are conditional. Rendering does not create a tag, signed artifact, registry package or tap change |

Each subdirectory retains its original `artifact-manifest.json`; every selected
file was verified before and after copying. [archive-verification.json](archive-verification.json)
records the counts and manifest hashes. Binaries, downloaded packages, caches,
keyring/vault state and private DBus sockets are excluded. The only retained Go
helper is inert text (`.go.txt`), so the archive cannot add a Go package.

The directory date is the original session label. Raw records retain October
30–31 UTC timestamps; documentation assembled November 3 in America/New_York
does not rewrite them. The first Linux driver's final vault-extension assertion
failed after the behavior completed; its original record is retained separately
from the clean run in `native-linux/final/`.

The native macOS Keychain CI job is separate proof and requires an observed CI
result before being called passed. Neither it nor this Linux probe closes the
Mac/Codex/Claude Code/OpenCode or Linux desktop/Cursor human-host matrix, native
desktop unlock UX, signed-release installation, npm bootstrap or Homebrew
migration. See [HOST_E2E.md](../../HOST_E2E.md) and
[LAUNCH_READINESS.md](../../LAUNCH_READINESS.md).

`v0.5.1-rc.1` is a proposed next preview candidate, not a created tag. The release
workflow publishes verified GitHub assets for `v*` tags, so tagging is held for
the remaining native-host and installation readiness decision. No release tag,
registry publication, tap update, arXiv submission or Vercel production promotion
is established by this archive.
