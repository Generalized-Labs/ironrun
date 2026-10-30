# Reproducing the evaluation evidence

The paper separates the **October 21 paired leakage reproduction** from the
**October 22 current-only diagnostics**. All credentials are synthetic; no
provider calls or real credential values are required. Nonzero exit, missing
sentinels, unsupported isolation, and skipped tests are not successful evidence.

## Paired leakage reproduction, October 21

Both runtimes were built with Go 1.26.10 on Linux amd64 and used the same checked
evaluation harness, including returned-error, child-exit and output-sentinel
checks. The v0.5.0 runtime and its dependencies were unchanged; only the harness
was copied into that source tree.

| Runtime | Cases meeting the 50% recovery threshold | Accidental subset |
| --- | --- | --- |
| v0.5.0, `d16e04b09ec8c24e6d6e255caad9209182635af8` | 52/126 | 21/72 |
| Reviewed runtime identified by the October 21 source manifest | 28/126 | 3/72 |

Recovery is case-insensitive longest contiguous matching after the decoder
battery. This deterministic corpus metric is not a deployment leak rate or a
usable-credential test. Below-threshold disclosure can expose a whole password
inside a longer URL. There are six single synthetic values and 21 transformations;
these are not 126 independent samples from a deployment population.

Raw outputs and exact source hashes are under `docs/validation/2026-10-21/`:
`go1.26.10-baseline-leak.txt`, `go1.26.10-current-leak.txt`, and
`go1.26.10-provenance.json`. Earlier Go 1.26.9 paired outputs and archive/harness
provenance remain under `docs/validation/2026-10-20/`. The reviewed runtime then
contained uncommitted fixes; its base Git commit alone does not identify the
measured code. Use the retained source hashes when assessing that result.

To reproduce a new paired comparison, use Go 1.26.10 and copy one exact checked
harness into both runtimes. From a checkout containing that harness:

```sh
go test ./paper/eval
go run ./paper/eval -only leak > current-leak.txt 2> current-leak.stderr.txt
baseline_dir=$(mktemp -d)
curl -fsSL https://codeload.github.com/generalized-labs/ironrun/tar.gz/d16e04b09ec8c24e6d6e255caad9209182635af8 -o "$baseline_dir/source.tar.gz"
printf '%s  %s\n' '60973e7ce01f37a72112ede8f37bb112c3ccda80a00a6d3f2431a5093b9b7721' "$baseline_dir/source.tar.gz" | sha256sum -c -
tar -xzf "$baseline_dir/source.tar.gz" --strip-components=1 -C "$baseline_dir"
mkdir -p "$baseline_dir/paper/eval"
cp paper/eval/main.go paper/eval/main_test.go "$baseline_dir/paper/eval/"
(cd "$baseline_dir" && go test ./paper/eval && go run ./paper/eval -only leak) > baseline-leak.txt 2> baseline-leak.stderr.txt
```

Check each exit status and stop on failure; the baseline example places test
output before its table. The baseline declares Go 1.26.5; building both sides
with Go 1.26.10 controls compiler version while retaining each runtime's own
module dependencies. This reproduces the comparison, not the original authors'
old machine or missing audit/performance records. Review temporary directories
before removing them.

## Fresh current-only diagnostics, October 22

The fresh run uses commit `a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d` with a clean
tracked tree at snapshot time and Go 1.26.10. Its raw records, manifests and
compressed frozen corpus are under
[`docs/validation/2026-10-22/fresh-pilot/`](../docs/validation/2026-10-22/fresh-pilot/).

The host was Linux amd64, Debian 13.6/kernel 6.18.55, Intel Xeon Platinum 8573C,
with three visible/affinity CPUs, cgroup CPU quota `200000/100000` microseconds
(two CPUs) and an 8 GiB memory limit. It was a shared host. GOMAXPROCS was not
explicitly set by the driver or measured. The exact Go executable SHA-256 was
`9c2a37ae5b21ba1d5a004bb9ab4d0c64de6fc5778e9d30487adccea62678b8b5`.

| Phase | Exit | Fresh result |
| --- | ---: | --- |
| `go test ./paper/eval` | 0 | Uncached harness checks passed |
| Build fixed evaluation binary outside the source tree | 0 | Binary SHA-256 `c2e95a3c610a675995f4699fe5cb6c8bc2ae105460e1e76ccdc39190c28bc50b` |
| `eval -only leak` | 0 | 126 successful sentinel-checked child probes; 28/126 threshold cases, 3/72 accidental; warnings on 21 threshold cases and six below-threshold cases |
| `eval -only fp` | 0 | Six format passes over 1,209,966 bytes; Postgres URL 1,002 replacement events, five other formats zero |
| `eval -only perf`, inside additional filesystem sandbox | 1 | Failed at first isolated spawn with `read-only file system`; partial output retained in `perf.*` |
| Same fixed binary `-only perf`, outside that additional sandbox | 0 | 34/21/9 MB/s for 1/10/50 values; median direct/runner/runner+no_network 1.042919/2.5609/3.34219 ms, each n=200; retained separately in `perf-outside-sandbox.*` |

The successful rerun did not disable the runtime's network isolation. The earlier
failed attempt is a separate result, not silently discarded. No fresh baseline
FP or performance run was made. The old paired leakage record does not turn
these current-only diagnostics into version comparisons.

### Frozen input and source identity

`source-manifest-before.json` hashes all 309 tracked files; the after-FP manifest
is identical. Its canonical manifest-entry-list SHA-256 is
`8a86286e4b6ac9841933a605a02e19088ff47c1a3422356b320926ddac74a936`.
`fp-corpus-manifest.json` records the lexical depth-first order, sizes, hashes and
concatenation offsets of all 209 Go/Markdown input files. Their 1,142,076 bytes
are followed by 67,890 bytes of exactly 1,000 generated DSN log lines. No snapshot
walk/read errors occurred; the harness's reported byte count matches the frozen
input. The decompressed corpus SHA-256 is
`b266fe95e7a15bf7caafc68580e2efa150e76b119e1102632bc2b0fe3b8cb056`.
The archive records the compressed artifact hash separately. Do not substitute a
current working-tree corpus: adding code, Markdown or validation records changes
what the harness reads.

### Repeating the pinned current protocol

Use a separate source directory at the measured commit so later paper/product
edits do not alter the FP input. These commands assume Go 1.26.10 on PATH and
cached dependencies or ordinary module-download access; the original pilot used
its prepared cache with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local` and
`GOFLAGS=-buildvcs=false`. Its complete explicit cache/state settings are retained
in `provenance.json`. The evaluation has only `-only leak|fp|perf`, with no JSON,
seed, ablation, corpus-file, threshold or tail-latency flags.

```sh
pilot_dir=$(mktemp -d)
mkdir "$pilot_dir/source" "$pilot_dir/results"
git archive --format=tar -o "$pilot_dir/source.tar" a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d
tar -xf "$pilot_dir/source.tar" -C "$pilot_dir/source"
cd "$pilot_dir/source"
export GOFLAGS=-buildvcs=false
run_pilot_phase() {
  pilot_phase=$1
  shift
  "$@" > "$pilot_dir/results/$pilot_phase.stdout.txt" 2> "$pilot_dir/results/$pilot_phase.stderr.txt"
  pilot_status=$?
  printf '%s\n' "$pilot_status" > "$pilot_dir/results/$pilot_phase.exit.txt"
  return "$pilot_status"
}
run_pilot_phase test go test ./paper/eval || exit
run_pilot_phase build go build -o "$pilot_dir/results/eval" ./paper/eval || exit
run_pilot_phase leak "$pilot_dir/results/eval" -only leak || exit
run_pilot_phase fp "$pilot_dir/results/eval" -only fp || exit
run_pilot_phase perf "$pilot_dir/results/eval" -only perf || exit
```

Run sequentially and preserve all output. If the host cannot execute the isolated
probe, retain that failure; do not replace the mode with an unisolated probe.
Use a host that supports the requested isolation for a complete run, preserving
any preceding failed attempt. Exact binary hashes can differ when build paths or
settings differ; record both runtime source and binary identity.

### Diagnostic limits

Throughput is the fastest of five scanning/flush repetitions over approximately
4 MiB of repeated no-match text in 32 KiB writes. Encoding generation and writer
construction are excluded. Values generated with `%024x` from 64-bit integers
share padded prefixes. Spawn modes run in fixed direct/runner/isolated order in
each repetition, and output retains medians only. No p95/p99, paired latency
increment, first-visible-byte delay, long-value scaling, provider latency or peak
memory result is established.

The FP result is a replacement-event count. The 1,000 deliberately similar DSN
log lines dominate the Postgres collision; changed bytes/lines and mixed-corpus
precision/recall were not measured. A below-threshold entropy warning need not
be a false alarm because partial sensitive components can still be exposed.
No human usability study was conducted. These records replace selected
unsupported old measurements; they do not recover historical audit totals or
validate every deployment.

## Current regression case studies and streaming checks

The manuscript's four lessons refer to source at
`a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d`:

| Lesson | Current source / checks |
| --- | --- |
| Review the enforced artifact | `cmd/ironrun/review_test.go`: `TestAppendCommandCannotInjectPolicyYAML`, `TestApproveBindsToReviewedProposalDigest` |
| Cover every reachable surface | `cmd/ironrun/cli_usability_test.go`: `TestVaultRootKeyShareCommandRemoved`; `internal/execution/github_masks_test.go`: `TestEmitGitHubMasks_MultiLineValueNeverPrintedRaw` |
| Account for encoding structure | `internal/redact/shapes_test.go`: `TestRedactBase64AtEveryAlignment`, `TestRedactJSONAndPercentEncodings`, `TestRedactHexDumpColumns`, `TestRedactLargeFileSecretFragments` |
| Avoid vacuous containment success | `internal/runner/net_test.go`: `TestNoNetwork_BlocksOutbound`, `TestNoNetwork_AllowsFork`; `net_internal_test.go`: `TestNoNetwork_FailsClosedWhenSandboxMissing` |

These are current behavior specifications, not an original defect-to-fix manifest
or a claim that every check failed on v0.5.0. Run them separately from the
`paper/eval` diagnostics, with exit status and any platform skips retained:

```sh
go test ./cmd/ironrun -run '^(TestAppendCommandCannotInjectPolicyYAML|TestApproveBindsToReviewedProposalDigest|TestVaultRootKeyShareCommandRemoved)$' -count=1
go test ./internal/execution -run '^TestEmitGitHubMasks_MultiLineValueNeverPrintedRaw$' -count=1
go test ./internal/redact -run '^(TestRedactBase64AtEveryAlignment|TestRedactJSONAndPercentEncodings|TestRedactHexDumpColumns|TestRedactLargeFileSecretFragments|TestStreamingMatchesBatch)$' -count=1
go test ./internal/runner -run '^TestNoNetwork_' -count=1
go test ./internal/redact -run '^$' -fuzz '^FuzzRedact$' -fuzztime=10s
```

`TestStreamingMatchesBatch` contains 3,000 deterministic cases and 1–13-byte
chunks. `FuzzRedact` is a separate bounded fuzz campaign with its own seed corpus;
record the duration, seed/artifacts and failures of each campaign. A passing
current run does not recreate missing historical RQ4 results. Darwin-only
network/fork checks do not execute on Linux, and an isolation-unavailable skip
is not a successful enforcement sample. No new race-suite outcome is inferred
from the harness-only pilot; retain the separate final race-suite result with
the publication source.
