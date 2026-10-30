# Citation review: 82 cited references

The reviewed manuscript is commit `bccf7547280804c8cef915a3510b099c99e38cfd`.
All **82 cited entries** are represented in `citation-matrix.json` and the CSV.
The bibliography contains 86 entries; four are uncited. This review completed on
October 24, 2026 using retained October 23 web extractions and targeted metadata
follow-ups. It made no repository changes.

## Material corrections

1. **Secretless Broker is not HTTP-only.** Its official README explicitly lists
   MySQL, PostgreSQL, SSH/SSH-Agent (beta), HTTP, and connector extensions.
   The reviewed discussion at lines 917–925 and related-work grouping around
   line 1026 cannot use database protocols or SSH as categorical exclusions from
   credential brokering. Keep HTTP-only limits attached to HTTP-specific
   proxies; describe unsupported connectors, local signing, and local file
   consumers as narrower remaining cases. Source:
   <https://github.com/cyberark/secretless-broker>.
2. **LangWatch redacts at ingestion.** Its current documentation says redaction
   runs before storage and describes local scrubbing before report upload.
   The reviewed line 1037 incorrectly groups it exclusively with after-the-fact
   history cleanup. That timing does describe agent-sweep's repository purpose.
   Source: <https://langwatch.ai/docs/coding-agents/secrets-redaction>.
3. **Current host filesystem controls need a qualified comparison.** The
   reviewed introduction's blanket claim that host rules hiding `.env` cannot
   stop indirect reads is too broad. Current Claude sandbox documentation
   describes enforced filesystem read denial for sandboxed commands, including
   `.env` examples. Historical incident reports motivate caution but do not
   establish universal current-client limitations. Scope the claim by tool,
   configuration, and execution channel. Source:
   <https://code.claude.com/docs/en/sandboxing>.

Short supporting quotations and facts are retained in
`critical-scope-evidence.json`; the matrix gives original citation contexts.

## Metadata and version checks

No fabricated reference or confirmed scholarly title/author/year error was
found. Two apparent title mismatches are legitimate version distinctions:

- **Progent:** the bibliography title, “Securing AI Agents with Privilege
  Control,” matches arXiv v3 (May 14, 2026). An earlier retained abstract showed
  the v1/v2 title. Optionally pin the URL to
  <https://arxiv.org/html/2504.11703v3>.
- **Parasites in the Toolchain:** the publication title and all nine authors
  are confirmed by the official S&P 2026 accepted-paper list. The arXiv URL
  retains “Mind Your Server.” Prefer adding the publication DOI
  `10.1109/SP63933.2026.00154` or a publisher URL so readers can reconcile them.

Crossref/publisher records corroborate MCPTox's volume/issue/pages, both Basak
papers, Huang's core article metadata, and Sigstore. The full Sigstore title is
supported by the publisher despite a shortened Crossref title. These results and
exact source URLs are in `metadata-crosscheck.json`.

Limits: Huang's unused `articleno=111` was not independently reconfirmed.
The `sandbox-exec` command and deprecation are corroborated through macOS manual
mirrors. A prior “checked on macOS 26.4” note remains a prior author observation;
this Linux review cannot validate it. Adding a retrievable manual URL and
distinguishing access year from publication year would improve traceability.

## Claims that require careful interpretation

- Chen's **1,007/1,371 (73.5%)** figure concerns categorized vulnerability issues
  in a 17,022-skill study, not every skill or a production leak probability.
- Panfilov's paper explicitly reports **182 credentials** recovered from hidden
  reasoning blocks. It supports this disclosure channel; it does not imply
  every context value necessarily reappears there.
- GitGuardian reports are vendor observations, not causal proof that AI
  assistance caused a particular leak. The 2026 report describes 2025 data.
- Knostic, Eve, and GitHub issues are dated reports/anecdotes. Current docs and
  historical incidents answer different questions.
- Current fnox and Prismor docs support overlapping tool/secret restrictions,
  command policy, approval, and filtering. They do not establish historical
  priority or equivalent enforcement. No firstness claim is justified here.
- The Schneier–Kelsey and Crosby–Wallach references are background for secure
  audit structures. They do not give an unkeyed local hash chain authenticated,
  forward-secure, or monotonic properties; a Merkle structure alone is not an
  independently trusted anchor.
- Kernel/manpage/Sigstore references describe mechanisms. Actual filter setup,
  platform behavior, and release authenticity require their separate tests and
  artifact verification.

## Exact coverage and limits

| Evidence level | Cited entries |
| --- | ---: |
| Retained text extracted from a primary URL, including landing pages, abstracts, source, or selected documentation | 78 |
| Additional publisher/official-page/Crossref corroboration completing initially missing cited DOI records | 3 |
| macOS manual mirror corroboration | 1 |
| Total reference identities and original citation contexts accounted for | 82 |

“Primary URL text” does not mean the entire external paper was read or its
experiments replicated. Author/year/page fields were not exhaustively normalized
for every entry. The matrix explicitly records the stronger targeted checks,
partial fields, scope corrections, and weaker evidence classes. Link
availability, metadata consistency, substantive support, and independent
replication are separate checks. This report is not a claim that every sentence
of Ironrun or every external study is proved correct.

The completion reused ten prior numbered Exa search-response files, seven
numbered fetch batches, a critical fetch, and product fetches. The follow-up added
no new search calls, one Exa batch of five URLs, six Crossref requests (five
successes and one retained HTTP 429 failure), and one official S&P HTML request.
Prior requested search-result totals are not retained, so no invented
“sources reviewed” count is reported.

`raw-evidence-inventory.json` hashes the retained input files without duplicating
full external source pages. `citation-matrix.json` identifies source URLs,
retained text hashes, metadata scope, claim notes, and original line contexts.
The parent should record which findings are corrected in the final manuscript;
this matrix deliberately preserves the reviewed commit's findings.
