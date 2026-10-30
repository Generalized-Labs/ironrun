# Workspace networking, host integration, and deeper paper review

The approved workspace path now implements the normal network access promised
by its approval screen, stored grant, and CLI. The maintainer explicitly chose
that behavior; saved policy commands keep their own network policies. The option
is set after workspace authorization. A Linux integration regression exercises
actual CLI approval/revocation, MCP, encrypted environment storage, a child HTTP
request, and filtered returned output, using synthetic root-key storage.

| Archive | Retained evidence and limits |
| --- | --- |
| [e2e](e2e/README.md) | Behavioral red/green and six focused race checks for the workspace/strict-command network distinction; earlier sandbox setup failures remain separate; native root-key store substituted |
| [runtime](runtime/README.md) | Final demo-copy follow-up passes uncached full Go race, vet, Staticcheck and compiled-copy CLI smoke; earlier 11 release regressions and 19 Node 24 tests with zero skips retain separate source identities; 182 stable Go/module inputs |
| [codex-host](codex-host/README.md) | Actual Codex CLI → stdio MCP → human-approval fixture → child loopback → redacted tool output → next model request; scripted local model, synthetic key-store adapter, and explicit isolated host approval configuration |
| [snapshot](snapshot/README.md) | Two unpublished four-platform builds, archive/checksum/SBOM checks, and Linux amd64 help/version smoke; source changed between builds, so no reproducibility claim; diagnostic casks must not be installed or published |
| [analysis](analysis/README.md) | Pinned Graphify code-only map of 194 current source files, selected authorization/network surface with manually checked alias bridges, and REA Go metadata/ELF header observations for the final binary; static navigation does not prove runtime enforcement; optional native layout/decompiler providers unavailable |
| [paper](paper/README.md) | Final 14-page, five-figure, four-table paper with confirmed author order; 1,815-character matching abstract; three-pass extracted no-shell-escape build; all 14 new pages inspected; earlier method/proof evidence preserved separately |

The final tested `mcp/server.go` SHA-256 is
`c585b0004ea56fa2de402987269ed1caa0446795b19648dab2caaa47dc0464d2`.
Base commit `64308e6` precedes the uncommitted repair and copy changes; the per-file
manifests identify tested source. The focused regression's original records use
the earlier `9efac543…` server. Later copy-only deltas and full-suite/host
captures are recorded separately instead of transferring an older result to
different bytes. Snapshot manifests retain their own boundaries.

The final executable-source change corrects three guided-demo print strings in
`cmd/ironrun/init.go`, now
`ccf08e39b4ceb7cc80aa2657b6d280b999738704caa1ad9bdf8981c2ea2d9d0a`.
The README diagram separately narrows its wording to registered matches.
The [final runtime follow-up](runtime/demo-copy-followup/README.md) passes after
those changes. Host, snapshot and Graphify records retain the preceding source
and binary hashes; the [two-path delta](runtime/demo-copy-followup/source-delta.json)
records that distinction. An archived Go overlay was renamed to inert `.go.txt`
before the final passing broad suite; the initial packaging failure is retained.

The deeper paper revision strengthens the matcher proof, recovery metric, and
evidence-provenance explanation. The final author-only change orders Stephen
Keehn before Mihir Gupta and omits unconfirmed affiliations. It does not alter
the body or measured results. Earlier leakage/performance evidence retains its
own measured source and frozen inputs under the October 21–22 archives; the
current product checks do not retroactively update those measurements.

The `2026-10-26` directory is a continuing session label. Original raw records
retain actual October 27 UTC times, and fresh verification/author build records
retain October 30 UTC times. User-facing documentation is updated October 29 in
the user's timezone. No timestamp is rewritten to match the archive path.

This evidence does not establish native Keychain/Secret Service behavior,
interactive approval usability, real-model judgment, other installed agent
hosts, macOS runtime behavior, signed tagged installation, or sustained daily
use. The [host checklist](../../HOST_E2E.md) and
[launch readiness](../../LAUNCH_READINESS.md) retain those gates. All-author
agreement to the paper's proposed CC BY 4.0 license is still unconfirmed.
No merge, release tag, registry publication, tap update, or arXiv submission is
performed by these checks.

Each subdirectory's artifact manifest hashes its retained files and excludes
itself. Raw log bytes are preserved. Skips and setup failures are not positive
evidence of enforcement.
