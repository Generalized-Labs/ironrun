# Fresh existing-harness diagnostic, 2026-10-22

This archive records a fresh shared-host pilot of the existing evaluation harness at commit `a4ab72e475bb6d3ed548e0dd7569294a1b3a0e8d`, using Go 1.26.10. It preserves both the initial performance failure inside the agent filesystem sandbox and a later successful performance run outside that sandbox. Network namespace isolation remained enabled for the successful run's `runner+no_network` probes.

The harness credentials and generated log lines are synthetic. The frozen false-positive corpus contains public tracked source/documentation and those generated log lines. No credential providers or environment files were read. This evidence does not reconstruct the historical audit or validate historical timing tables. No product or evaluation source was changed by this pilot or its archival packaging.

## Recorded outcomes

The original driver phases ran sequentially from `/workspace/ironrun-product-review` in the order `prepare`, `test`, `build`, `leak`, `fp`, `perf`. A single evaluation executable was built outside the repository and held fixed. Its original build metadata and SHA-256 are retained; **the executable itself is not included in this archive**.

| Phase | Exit | Recorded result |
| --- | ---: | --- |
| `go test ./paper/eval` | 0 | Successful uncached harness-package test, reported `0.002s` |
| `go build -o .../fresh-pilot/eval ./paper/eval` | 0 | Built the fixed evaluation executable |
| `eval -only leak` | 0 | 126/126 child probes completed with successful-exit and output-sentinel checks; 28/126 met the at-least-50% recovery threshold; accidental subset 3/72 |
| `eval -only fp` | 0 | Six format passes over the frozen 1,209,966-byte corpus; 1,002 replacement events for the structured Postgres URL and zero for each other format |
| `eval -only perf`, inside filesystem sandbox | **1** | Throughput rows completed; first network-isolated spawn probe failed with `read-only file system`; no spawn medians emitted |
| `eval -only perf`, outside filesystem sandbox | **0** | Throughput rows and all three 200-sample spawn modes completed, with network namespace isolation enabled for `runner+no_network` |

Leakage output also records 21 warned threshold leaks and six warned cases among the 98 below-threshold cases. Below the aggregate threshold does not imply absence of useful sensitive-component disclosure. These are results for a deterministic six-value by 21-transformation corpus, not a deployment leak rate. This pilot did not run a fresh baseline.

### Two distinct performance records

`perf.result.json`, `perf.stdout.txt`, and `perf.stderr.txt` preserve the original inside-sandbox attempt unchanged. Its exact failure was printed on stdout; stderr was empty:

```text
error: isolated probe: execution failed: runner: exec error: fork/exec /workspace/ironrun-product-research/fresh-pilot/eval: read-only file system
```

That process completed 15 throughput repetitions. From its deterministic control flow and failure location, one direct and one sealed spawn succeeded before the first isolated attempt failed; these two successful counts are inferred rather than emitted independent samples. The initial failed result is not replaced or reclassified as passing.

The later run executed this exact command outside the agent filesystem sandbox:

```sh
/workspace/ironrun-product-research/fresh-pilot/eval -only perf
```

Its separate records are `perf-outside-sandbox.stdout.txt`, `perf-outside-sandbox.stderr.txt`, and `perf-outside-sandbox.result.json`. The supplemental result JSON records the supervising agent's observed exit code 0 and hashes the retained raw output. This invocation was not wrapped by `pilot_driver.py`: start/end timestamps, elapsed walltime, per-sample durations, and outside-run load/cgroup counters were not captured and are not reconstructed. Their absence is explicit in the result JSON. The initial provenance's explicit environment and phase counters must not be treated as an independently recorded environment or load snapshot for this later invocation.

Both attempts printed these throughput rows:

| Injected values | Registered patterns | MB/s |
| ---: | ---: | ---: |
| 1 | 18 | 34 |
| 10 | 180 | 21 |
| 50 | 900 | 9 |

The harness reports the fastest of five scanning/flush repetitions per row on 4 MiB of neutral text in 32 KiB writes. Encoding generation and matcher construction are outside its throughput timer. The completed outside-sandbox run additionally printed:

| Spawn mode | Median, ms | Samples |
| --- | ---: | ---: |
| Direct | 1.042919 | 200 |
| Runner | 2.5609 | 200 |
| Runner with network namespace isolation | 3.34219 | 200 |

These are fresh shared-host diagnostics, without a controlled performance claim or available p95/p99 values. Raw per-sample timing distributions were not emitted. Completing the isolated probe verifies that this synthetic invocation succeeded under the requested namespace setting; it does not establish all containment properties.

## Frozen source and corpus

`source-manifest-before.json` hashes 309 tracked source-snapshot entries, and `source-manifest-after-fp.json` is identical. Original provenance records a clean Git tree at the snapshot. During archival packaging, all 309 entries were independently checked against Git blob contents at the pinned commit, rather than against the subsequently changing working tree. `source-verification.json` records that check.

`fp-corpus-manifest.json` lists 209 `.go`/`.md` inputs in the harness's lexical, depth-first `filepath.WalkDir` order, including each input's SHA-256, byte length, and concatenation offset. All 209 inputs were verified to be tracked at the pinned commit. The frozen corpus contains 1,142,076 source/documentation bytes plus 67,890 bytes from exactly 1,000 appended synthetic log lines. Directory names `.git`, `.claude`, and `paper` were excluded, matching the harness. Snapshot traversal/read errors were zero; the harness-reported byte count matches the snapshot.

The exact corpus is included as `fp-corpus.bin.gz`: gzip level 9, zero modification time, and an empty embedded filename. Decompression reproduces the original `fp-corpus.bin` bytes exactly. Packaging also regenerated those bytes from the committed input files and appended log lines and confirmed equality. The original uncompressed file is omitted to avoid storing the same corpus twice.

| Identity | SHA-256 |
| --- | --- |
| Canonical source-manifest entry list, serialized by `pilot_driver.py` | `8a86286e4b6ac9841933a605a02e19088ff47c1a3422356b320926ddac74a936` |
| Frozen corpus, uncompressed | `b266fe95e7a15bf7caafc68580e2efa150e76b119e1102632bc2b0fe3b8cb056` |
| Frozen corpus, archived gzip | `5cabc452a9cd81e8216b40ed800dc0931e9d1ebff179c05dd0f4a58dca21b2b5` |
| Evaluation executable used, omitted from archive | `c2e95a3c610a675995f4699fe5cb6c8bc2ae105460e1e76ccdc39190c28bc50b` |
| Verified Go executable used | `9c2a37ae5b21ba1d5a004bb9ab4d0c64de6fc5778e9d30487adccea62678b8b5` |
| Exact archived driver | `0f368d4d48118f04d68351595d7eece3df5cfa7ca00f9e9558710fe78ce84161` |

`artifact-build-info.txt` retains Go module/build metadata for the omitted executable. `provenance.json` preserves original source, toolchain, explicit cache/state settings, kernel/OS, affinity, cgroup, and initial-load records. Only explicitly selected diagnostic environment settings were recorded. Dependency fetching was disabled with `GOPROXY=off`, `GOSUMDB=off`, and `GOTOOLCHAIN=local` because dependencies were already cached. `GOFLAGS=-buildvcs=false` avoided a known VCS lookup problem in subprocesses.

## Archive inventory

`artifact-manifest.json` inventories every included file except itself, by relative path, byte length, and SHA-256. It describes this archive, including the compressed corpus, copied driver, and supplemental outside-sandbox record. `original-artifact-manifest.json` preserves the earlier research-directory inventory unchanged as historical provenance. That older inventory references the excluded executable, uncompressed corpus, and original pre-update README/summary; it is **not** the inventory of the committed archive.

From this archive directory, verify included files without executing the harness:

```sh
python3 - <<'PY'
import gzip, hashlib, json
from pathlib import Path

root = Path('.')
manifest = json.loads((root / 'artifact-manifest.json').read_text())
expected = {entry['path'] for entry in manifest['files']}
actual = {p.name for p in root.iterdir() if p.is_file()} - {'artifact-manifest.json'}
assert actual == expected
for entry in manifest['files']:
    data = (root / entry['path']).read_bytes()
    assert len(data) == entry['bytes'], entry['path']
    assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
corpus = gzip.decompress((root / 'fp-corpus.bin.gz').read_bytes())
assert len(corpus) == 1209966
assert hashlib.sha256(corpus).hexdigest() == 'b266fe95e7a15bf7caafc68580e2efa150e76b119e1102632bc2b0fe3b8cb056'
print('Archive inventory and frozen corpus verified')
PY
```

## Reproduction and limits

`pilot_driver.py` is copied byte-for-byte from the driver used for the original phases; its hash matches original provenance. It contains the exact commands, source/corpus snapshot construction, selected environment settings, per-phase capture, and error checks. The script uses the original absolute paths. To reproduce elsewhere, use a writable copy, point `REPO`, `OUT`, `TOOLS`, and its two XDG directories at the corresponding locations, and record the adjusted driver hash. Use Go 1.26.10 with required dependencies available, a **separate clean checkout at the pinned commit**, and an output directory outside that checkout. The archive's newly added `.md` files would themselves change the false-positive inputs if reproduction ran over the current checkout.

Invoke the copied driver in the recorded order: `python3 pilot_driver.py prepare`, then `test`, `build`, `leak`, `fp`, and `perf`, checking each exit. Compare the newly generated source/corpus identities before interpreting results. Rebuilding from a different absolute path may change the executable hash; its recorded hash identifies the original artifact rather than promising a path-independent rebuild. Running the final performance command outside an agent filesystem sandbox requires an environment where its namespace-isolated probe can execute; it does not require disabling that namespace isolation.

The existing harness has no corpus-file flag. The archived gzip is an exact replay fixture for a future explicit corpus reader, not a supported input argument to `-only fp` today. Do not substitute a changed source corpus and label its result as reproduction of this frozen input.

Original host context: Debian GNU/Linux 13.6, kernel 6.18.55, linux/amd64, Intel Xeon Platinum 8573C, three visible/affinity CPUs, two-CPU-equivalent cgroup quota, and an 8 GiB memory limit. `GOMAXPROCS` was not explicitly set or measured. This was a shared host/container. Original per-phase load and CPU counters are available; counters for the later outside-sandbox invocation are unavailable.

The deliberately similar DSN log lines dominate structured-URL collisions. Aggregate replacement events do not supply changed-byte/line counts or mixed-corpus precision/recall. Matching an older aggregate count does not establish identical historical inputs. The throughput corpus has no inserted matches, uses one write size, and omits construction costs. No first-visible-byte, quiet-process, long-value, controlled scaling, tier-ablation, or tail-latency experiment was added.

Useful next measurements are component-sensitive leakage with useful-output preservation; controlled representation/tier ablation with a fixed benign corpus; and end-to-end delivery latency/scaling including long values. Those need explicit instrumentation and new recorded samples. They are proposed work, not results inferred from this archive.
