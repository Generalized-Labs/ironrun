# Source, artifact, and prior-work follow-up

Reviewed October 21, 2026 (America/New_York). Graphify and REA inspected clean
commit `803aa420d35af969ca4ff858a374a7dcdf20796d`. The later changes in this
follow-up correct the paper and documentation; Go/npm runtime source is unchanged.
Source hashes identify the captured snapshot even after subsequent paper edits.

## Evidence

- [Graph summary](graph-summary.json) and [provenance](graph-provenance.json):
  1,849 nodes, 6,593 raw links (6,139 EXTRACTED, 454 INFERRED), 6,564 unique
  undirected endpoint pairs, and 73 communities. The prior graph was simple;
  the new graph preserves parallel relations. Comparable pair growth is 90.
  Counts were independently recomputed from the raw graph.
- [REA review](REA_REVIEW.md), [compact results](rea-summary.json), and
  [source provenance](rea-source-provenance.json): the fresh development binary
  reports Go 1.26.10, revision `803aa42`, `vcs.modified=false`, and the expected
  build flags. npm analysis parses 11 JS files with zero parse failures, but its
  application coverage is partial and semantic coverage unknown. Structural
  observations and unresolved relations are not vulnerability findings.
- [Primary web check](WEB_REVIEW.md): official arXiv, version-specific cosign,
  and 1Password sources, with local metadata checks and evidence limits.
- [Closest-system review](PRIOR_WORK_REVIEW.md): fnox and Prismor first-party
  documentation and pinned source. Current Prismor documentation includes
  command policy and human approval in addition to output filtering; fnox has
  tool/secret allowlists. The manuscript now acknowledges the overlap and avoids
  broad missing-design/firstness wording. Current sources do not establish the
  historical introduction dates or equivalent enforcement semantics.
- [Paper build record](paper-build-summary.json): updated 14-page PDF, unchanged
  1,905-character ASCII abstract, and independently compiled extracted source
  bundle. Contact sheets for all pages show no obvious clipping. Final logs have
  no undefined citations/references or overfull boxes; a monospace italic font
  fallback remains.

Graphify's manually checked paths cover npm verification/spawn, proposal review
through policy execution, and runner/redactor wiring. Callback/event ordering,
function-variable aliases, and implicit writer data flow have extraction gaps.
The graph does not establish authorization correctness or the redaction theorem.

## Raw artifacts and scope

The full graph JSON, interactive HTML, REA output, local binary, build logs,
source archive, and page previews remain in this workspace under
`/workspace/ironrun-analysis/followup-803aa42/`. The HTML is
`graphify/graphify-out/graph.html`; it loads vis-network from unpkg.com when
opened. Analysis used local extraction and no model backend. REA inspected build
metadata and inert JS source; it did not decompile native code or execute the
Ironrun artifact. No secret provider or credential was used.

This evidence does not replace final-release signatures/SBOMs, platform and
external-user checks, or the missing historical audit/performance records. The
bootstrap npm manifest still intentionally refuses publication. Author/order,
paper-license, and preview-versus-stable questions remain with the user.
