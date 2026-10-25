# October 24 launch and paper follow-up

The current repairs pass the uncached Linux Go race suite, vet, 11 release
regressions, and 19 Node 24 launcher tests. Two unpublished four-platform builds
and five REA captures provide additional bounded evidence. The revised paper
builds from both working sources and an extracted three-file arXiv bundle.

| Archive | Evidence and limits |
| --- | --- |
| [runtime](runtime/README.md) | Red/green setup and deadline regressions, full race/vet/release/Node logs, exact tested Go/module/release/npm hashes; expected red failures retained |
| [rea](rea/README.md) | Four synthetic noninteractive setup cases and one actual local MCP request; config preservation and stored review deadline; no real host/model connection |
| [snapshot](snapshot/README.md) | Two four-platform builds, checksums, four retained SPDX SBOMs and native Linux help/version smoke; matching binary pairs, differing archive timestamps; no signing/publication |
| [citations](citations/RESOLUTIONS.md) | All 82 cited references reviewed in context, original findings preserved, final manuscript corrections hashed; excerpt/metadata review, not external experiment replication |
| [overlap](overlap/README.md) | Reproducible 22/23-byte residual overlap example; disproves a universal eleven-byte bound without changing matcher policy |
| [paper](paper/README.md) | Final 14-page PDF/source identities, 1,815-character synchronized ASCII abstract, three-pass pdflatex-only bundle check and visual review |
| [ci-followup](ci-followup/README.md) | CI identified two capitalized error-message openings; wording-only patch, focused race regressions, pinned staticcheck, exact updated source identity |

Base HEAD `bccf754` precedes these uncommitted repairs. Per-file manifests identify
the tested runtime and final manuscript; an embedded base commit alone does not.
The principal evidence was delivered in `5320554`; the later staticcheck wording
fix has its own source/status record rather than rewriting earlier measurements.
The earlier leakage and performance measurements retain their own pinned
sources and frozen inputs under the October 21–22 archives. No new performance
benchmark or human usability result is claimed here.

Independent reviews checked the runtime repairs and corrected paper/security
claims. No material finding remained in their reviewed scope. The README's stale
macOS timing and absolute disclosure claims were also corrected. This is not
exhaustive review, a proof of all program behavior, or a security certification.

REA and Graphify's earlier architecture-navigation outputs remain linked in
[REVERSE_ENGINEERING.md](../../REVERSE_ENGINEERING.md). The Graphify map is from
an earlier source; it is not represented as a new current-runtime validation.
Official arXiv metadata and TeX instructions were fetched again for this pass;
the selected PDFLaTeX processor and bundled bibliography match that guidance.

No real credentials or actual client configuration were used. No merge, tag,
release, registry publication, tap update, or arXiv submission was performed.
The remaining native-host, developer-pilot, tagged-signing/install, and author
agreement gates are listed in [LAUNCH_READINESS.md](../../LAUNCH_READINESS.md).

Each subdirectory's `artifact-manifest.json` hashes its retained files and
excludes itself. Raw log bytes are preserved, including trailing whitespace;
do not interpret a platform skip or a tool observation limit as a passed test.
