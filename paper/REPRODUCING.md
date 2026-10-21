# Reproducing the leakage comparison

Verified October 20, 2026 on Linux amd64 using Go 1.26.9. Both runs use the
same current evaluation harness, including successful-exit and output-sentinel
checks. The v0.5.0 runtime is unchanged; only the harness is copied into it.
No real credentials are required. All credential-shaped values are synthetic.

| Runtime | Cases meeting the 50% recovery threshold | Accidental subset |
| --- | --- | --- |
| v0.5.0, `d16e04b09ec8c24e6d6e255caad9209182635af8` | 52/126 | 21/72 |
| Reviewed working tree | 28/126 | 3/72 |

Recovery is case-insensitive contiguous matching after the decoder battery.
These are results for a deterministic microbenchmark, not real-world leak rates.
Partial disclosure below 50% can still be security-relevant. These runs do not
validate the self-audit tally, historical performance tables, false-positive
experiment, or RQ4 containment results.

## Commands

Run from the repository root with Go 1.26.9 on PATH:

```sh
go test ./paper/eval
go run ./paper/eval -only leak > current-leak.txt
baseline_dir=$(mktemp -d)
curl -fsSL https://codeload.github.com/generalized-labs/ironrun/tar.gz/d16e04b09ec8c24e6d6e255caad9209182635af8 -o "$baseline_dir/source.tar.gz"
printf '%s  %s\n' '60973e7ce01f37a72112ede8f37bb112c3ccda80a00a6d3f2431a5093b9b7721' "$baseline_dir/source.tar.gz" | sha256sum -c -
tar -xzf "$baseline_dir/source.tar.gz" --strip-components=1 -C "$baseline_dir"
mkdir -p "$baseline_dir/paper/eval"
cp paper/eval/main.go paper/eval/main_test.go "$baseline_dir/paper/eval/"
(cd "$baseline_dir" && go test ./paper/eval && go run ./paper/eval -only leak) > baseline-leak.txt
```

The baseline harness test output precedes its table in this example. Execution
warnings go to stderr; a nonzero exit must be treated as a failed experiment,
never as evidence of successful redaction. Review the temporary directory before
removing it.

## Evidence and scope

Raw outputs and provenance are under `docs/validation/2026-10-20/`:
`baseline-leak.txt`, `current-leak.txt`, and `leak-comparison-provenance.json`.
The provenance records the baseline archive hash, harness hash, current runtime
source hashes, host, toolchain, and Git base commit. The current tree contains
uncommitted fixes, so its base commit alone does not identify the tested code.
A final publication must pin the committed current source as well.

The baseline declares Go 1.26.5; this comparison deliberately builds both sides
with Go 1.26.9 to keep the compiler constant. Baseline dependencies remain those
in the baseline's own module files. This is a fresh reproduction of leakage
counts, not a reconstruction of the authors' original machine or run logs.
