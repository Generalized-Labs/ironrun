# Resolution of the citation-review findings

Recorded October 24, 2026 against these exact working-tree bytes:

| File | SHA-256 |
| --- | --- |
| `paper/ironrun.tex` | `0945f00738bac85e28764c00d23dd3b6bbd1a24bb94a683643d1b15faa8141d0` |
| `paper/references.bib` | `189ea3e5bde9aee34422af6096fec44ab8fbeb6ed484609c9888fe58ed10cb14` |

The retained matrix/report review the earlier `bccf754` manuscript and have not
been rewritten to hide their findings. The subsequent manuscript addresses the
three material comparison themes as follows:

| Original finding | Final correction |
| --- | --- |
| Secretless Broker was treated as HTTP-only, leaving database/SSH work categorically outside brokering | Discussion and related work explicitly include Secretless database and SSH connectors. HTTP-specific restrictions remain attached to HTTP proxies. Local signing, direct file consumers, and unsupported connectors are the narrower remaining cases; supported brokering is described as preferable. |
| LangWatch was grouped solely with cleanup after disclosure | Related work says LangWatch filters traces before storage or upload; cleanup of existing histories is attributed separately to agent-sweep. |
| Hiding `.env` through host rules was described as unable to prevent indirect reads in general | The introduction now distinguishes per-tool restrictions from host-enforced filesystem controls that can protect indirect read paths. Historical incident reports remain motivation, not proof of a universal current host limitation. |

Targeted bibliography traceability improvements also follow the review:

- Progent's URL is pinned to arXiv v3, whose title matches the bibliography; the
  note identifies the May 14, 2026 revision and earlier v1/v2 title.
- Parasites in the Toolchain now includes publication DOI
  `10.1109/SP63933.2026.00154`, alongside its differently titled earlier arXiv
  record. The official publication identity is not silently replaced by the
  preprint title.
- The `sandbox-exec` entry now links the retrievable manual mirror, labels its
  October 24 access date, and removes the unsupported claim of a macOS 26.4
  check. This Linux review does not establish native macOS behavior.
- Proper-name brace protection improves bibliography title capitalization;
  this is editorial and adds no new empirical support.

The manuscript also makes the audit citations' role explicit: the local unkeyed
hash chain does not inherit authenticated or forward-secure guarantees from
secure-logging background references. It discusses rewrite/truncation and the
need for an independently protected external anchor. Other scope qualifications
are retained: Chen's statistic counts categorized issues, vendor and incident
reports are observations, and current competitor documentation establishes
neither historical priority nor equivalent enforcement.

These corrections resolve the identified scope/traceability findings. They do
not upgrade the underlying 82-entry excerpt/metadata review into full-text
external-paper validation or replication. The original report records the
remaining narrower metadata limit (Huang's unused article number was not
independently reconfirmed). The paper's own measurements retain their separate
pinned runtime, corpus, raw outputs, and limitations.
