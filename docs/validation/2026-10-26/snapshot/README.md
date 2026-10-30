# Unpublished release-style snapshot evidence

This directory records two diagnostic builds of the reviewed runtime with
GoReleaser 2.18.2, Syft 1.55.0 and Go 1.26.10. It does not create a new release.
The local v0.5.0 tag gives the diagnostic snapshot version `0.5.1-next`;
maintainers have not selected that as the public preview version.

Use `verification-summary.json` for the observed outcomes and exact hashes.
`source-manifest-before.json` identifies the dirty Go/module/configuration and
archive-input bytes. Build metadata embeds base commit `64308e6`, which alone
does not identify the uncommitted workspace-network repair and catalog copy.
The source manifests after each run preserve the state at those boundaries.
Run 1 compiled and archived the earlier copy; a help/catalog/README copy pass
landed during its SBOM phase. Run 2 used the final copy, unchanged between its
recorded boundaries. The differing binaries and README members are reported;
these runs do not establish binary reproducibility. Individual compiler file
reads in run 1 were not traced.

GoReleaser configuration checking is separate from the snapshot pipeline's
skipped validation. Before hooks, signing, publishing and announcements are
skipped; the configured SBOM generation is enabled. The archive checksum and
SPDX JSON checks do not validate signatures, complete SPDX schema conformity,
native secure-storage behavior, installation, or a future published release.
Only Linux amd64 CLI help/version smoke commands are executed; the other three
platform binaries are cross-compiled files.

Generated casks are retained for inspection of template output and archive
checksums. Their diagnostic version is `0.5.1-next`, while snapshot-mode URLs
refer to the existing `v0.5.0` tag. Do not install or publish these recipes. A
real tagged release must regenerate and verify version, URLs and checksums.

The existing tool executable hashes are rechecked against retained official
download/checksum provenance from the earlier build. Checksum-file signatures
were not independently verified. No credentials, tags, release publication,
npm account or Homebrew tap writes are involved in this task.

This directory is the compact source-control handoff: raw statuses/logs, source and
tool identities, archive metadata/checksums, four run-2 SBOMs, and exact bundled
documentation/configuration/installer inputs. It deliberately excludes large
binaries, archive downloads, smoke-state directories and duplicate run-1 SBOMs.
`full-workspace-inventory.json` identifies the large local outputs by hash; those
files are not implied to be present in the compact copy. `verify_snapshot.py`
requires the full local outputs to recheck archive/binary identity.

The selected artifact manifest excludes itself. Final outcome claims should be
read from the completed status records, rather than inferred from this protocol.

The `2026-10-26` archive path is the continuing launch-review session label.
The raw records retain the actual UTC timestamps: builds on October 27 and
final verification on October 30, 2026.
