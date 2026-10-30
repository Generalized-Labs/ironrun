# Current-source Graphify and REA review

Graphify 0.9.93 rebuilt a code-only map of the current implementation and tests:
194 hash-listed files, 1,919 nodes and 5,540 edges. The selected authorization and
network surface is retained as 49 raw nodes and 57 raw call/reference edges.
REA 6.7.0 independently observed embedded Go metadata and GNU objdump file
headers for the final run-2 Linux amd64 binary, SHA-256
`659e3862f64c5379892190f09dd4e92b35190ded4b8be20bde9a03f3e0cf2054`.

This is architecture navigation and bounded binary inspection. It does not
replace the [runtime regressions](../runtime/README.md),
[loopback regression evidence](../e2e/README.md) or
[host fixture](../codex-host/README.md). The original session archive uses the
October 26 folder label; these fresh commands ran October 30 UTC.

## Authorization and network review

The graph helped locate the two `makeRunHandler` branches and their distinct
authorization helpers. The following conclusions additionally required manual
source reading, with exact excerpts and full-file digests in
`source-excerpts.json`:

| Surface | Observed source behavior |
| --- | --- |
| Input selection | `mcp/server.go:210` rejects supplying both or neither saved-command ID and workspace argv. |
| Workspace authorization | `awaitWorkspaceAuthorization` resolves one environment, calls `AuthorizeWorkspace`, and waits for an accepted grant before returning it. Denial, expiry or context cancellation returns an error before execution. |
| Grant binding | `internal/access/access.go:440` accepts grants only for the matching session, project root and environment, with no pause/revocation and a future expiry. |
| Workspace execution | After that helper returns successfully, the handler calls `executeWorkspace` with the pinned environment and `AllowWorkspaceNetwork: true`. The package variable at `mcp/server.go:35` aliases `execution.RunWorkspace`. |
| Policy translation | `RunWorkspace` builds an in-memory v2 command whose `AllowNetwork` comes from that option, then uses the shared execution pipeline. It does not rewrite a saved command. |
| Saved commands | The separate handler branch calls `awaitRunAuthorization` and `executeCommand` with its selected policy/environment. It does not set the workspace-network option. Agent leases are additionally required only when `RequireAgentLeases` is configured. |
| Shared network policy | `Command.EffectiveNoNetwork` gives explicit `NoNetwork` precedence, then allows explicit `AllowNetwork`, otherwise blocks network for secret-bearing commands. `runner.Run` applies that result and returns an error when requested isolation cannot be configured. |
| Shared output path | Both branches enter `execution.Run` and `runner.Run`; each stdout/stderr redactor is upstream of its output cap. This is filtering of supported registered representations, not control over files or arbitrary transformed/network output. |

The normal-network option is assigned only in the workspace branch after the
local authorization wait. The ordinary saved-command path retains its policy.
These are source observations, not a formal proof about every possible runtime
state. The loopback regression supplies the relevant dynamic observations:
no request during its bounded pre-approval window, successful authorized
workspace request, blocked strict command and no request after revoke/deny.
That regression uses synthetic credentials and a replacement native key-store
adapter; those limits carry through to any readiness conclusion.

## Tool coverage and gaps

Graphify resolves `makeRunHandler -> awaitWorkspaceAuthorization`,
`makeRunHandler -> awaitRunAuthorization`, and `RunWorkspace -> Run`. It does
**not** connect the `executeWorkspace`/`executeCommand` function-valued aliases
or all imported receiver/package calls. In particular, the map alone does not
establish the full `AuthorizeWorkspace -> RunWorkspace -> runner.Run` path or
control-flow ordering. Those bridges above were checked directly in the source.
Four files yielded no symbols: `npm/bin/ironrun.js`,
`npm/scripts/postinstall.mjs`, `npm/test/build-manifest.test.js`, and
`npm/test/launcher.test.js`. No symbols does not mean no behavior.

The multigraph diagnostic reports eight directed endpoint-pair groups whose
relation variants collapse if represented as a simple `DiGraph` (5,540 raw
edges become 5,532 directed pairs). The retained subgraph preserves raw edge
records. Counts and graph reachability must not be treated as proof of
semantic coverage. Semantic extraction, LLM deduplication and clustering were
disabled; the graph reports zero input/output LLM tokens.

REA's build-info reader observes ELF amd64, Go 1.26.10, Linux, CGO disabled and
the embedded module/build settings. Its evidence explicitly does not recover
function names, types, source mappings or decompiled code. The objdump provider
retains a complete, successful file-header command observation and matching
before/after binary digest. Neither observation authenticates dependencies or
proves runtime security. The optional `inspect-binary-layout` call failed
because its pwntools provider is not configured; the full error is preserved.
Ghidra, Rizin and Kuna decompilers are also unavailable in the provider inventory.
No native decompilation or binary data-flow analysis is claimed.

## Reproduction and provenance

`graph-inputs.json` names the current source inputs and digests. Files were copied
verbatim into an isolated mirror, excluding historical `docs/validation` source
copies and configuration/credential stores. `source-preservation.json` verifies
all 194 mirror/current file digests still match. The dirty source includes the
final `mcp/server.go` hash `c585b000...`; base commit `64308e6` alone does not
identify it. The selected binary is bound to the final-copy source boundaries
in the [snapshot evidence](../snapshot/README.md).

Graphify was reconstructed from the official GitHub codeload archive at commit
`b90b9df7949bd04a15b40a1624af85d0a9cfdf04`. Its installed `cli.py` and
`extract.py` hashes match the earlier retained provenance. The source archive
hash and resolved package versions/download digests are retained; no source
archive signature was independently verified. Commands used an empty analysis
HOME and explicit environment, with code-only extraction and no provider keys:

```sh
graphify extract /path/to/code-mirror --code-only --no-dedup --no-cluster --out /path/to/analysis
graphify diagnose multigraph --graph /path/to/analysis/graphify-out/graph.json --json
rea inspect-go-binary /path/to/final-linux-binary --format json --full-output
rea inspect-with-objdump /path/to/final-linux-binary file_headers --format json --full-output
```

Exact argv, actual UTC times, output hashes and tool identities are retained.
The full local graph is identified by hash but omitted from this compact copy,
along with tool dependencies, source mirrors and binaries. No project runtime
source was modified, no production credentials were used, and no release was
published by this analysis. The artifact manifest excludes itself.
