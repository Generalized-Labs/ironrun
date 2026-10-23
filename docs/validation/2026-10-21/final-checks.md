# Final validation — October 21, 2026

Go 1.26.10; Linux amd64. Source starts from PR commit 9794795 plus the concurrency,
toolchain and packaging repairs in its follow-up. `go1.26.10-provenance.json`
identifies the tested source with SHA-256 hashes. No real credentials were used.

## Checks observed

- Complete `go test -race ./...`, vet and staticcheck: pass. Namespace tests ran
  outside the filesystem sandbox; Go build/cache/temp paths moved to workspace
  storage after the temporary filesystem filled. The environmental failure is
  not counted as a passing test.
- `govulncheck` 1.9.0: zero reachable vulnerabilities. Initial GitHub CI caught
  GO-2026-6809 in Go 1.26.9; requiring Go 1.26.10 resolves it. One advisory remains
  in a required module outside imported/called code.
- Vault and pending/approval concurrency regressions: red before repairs, green
  under the race detector afterward. Independent reviews found no remaining
  blocker in those fixes. See concurrency-review.md and focused raw logs.
- Actual MCP stdio probe: both conflicting variants accepted 23/30 before versus
  0/30 after. This is diagnostic evidence, not a statistical security bound.
- Offline release tests: 11 pass. Fixtures exercise installer/Action control flow
  and identity binding, including hyphenated prereleases; they do not validate
  real Sigstore cryptography.
- npm suite: 13 tests pass on Node 20/22/24 locally and in initial-head GitHub CI.
  Packed tarball installation also passes in CI. Launcher code is unchanged in
  the concurrency/toolchain follow-up.
- Expanded redactor fuzz smoke: 22,581 executions pass over 11 seconds with fixed
  patterns, batch/chunked equivalence and the existing leakage invariants. This
  run used Go 1.26.9; initial-head GitHub fuzz also passed. Complete Go 1.26.10 race
  testing includes the fuzz seeds.
- Final paired leakage experiments with the same harness and Go 1.26.10:
  baseline 52/126, accidental 21/72; current 28/126, accidental 3/72. Raw tables and
  baseline archive/source provenance are included or linked.
- GoReleaser 2.18.2 configuration check: exit 0 after Homebrew cask migration.
  Two final snapshots produced identical binary hashes on all four targets.
  Archive checksums and all four generated cask platform mappings verify; Linux
  amd64 `version` runs. Signing, SBOM, before hooks and publication were skipped.
- arXiv preparation: 14-page PDF and extracted source bundle compile. Abstract:
  1,905 ASCII characters. Minor monospace italic font fallback remains; no undefined
  citations or overfull boxes. The final references page is short.
- `git diff --check`: pass.

The Go 1.26.10 Linux amd64 archive was downloaded from go.dev and verified against
SHA-256 ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5.

The previous reports, snapshot hashes, and Go 1.26.9 runs remain in Git history and
in the older evidence. Consult PR 16 for final-head remote CI results; passing
checks on an earlier head do not establish the final head's status.

Open gates: actual signed-release verification, npm account bootstrap and final
manifest, Homebrew clean-install/upgrade and Apple signing behavior, remaining
architecture/proxy/read-only-cache tests, external-user checklist items, and
original historical self-audit/performance/false-positive/RQ4 records. See
../../LAUNCH_READINESS.md and ../../PAPER_REVIEW.md. No release or arXiv submission
has occurred.

For the gap-scan probe, copy gap-scan-probe.go.txt to main.go in a temporary module
named github.com/generalized-labs/ironrun/reviewprobe. Require Ironrun v0.0.0 and
replace that dependency with the absolute checkout path, then run go run . .
Shared-host timing is diagnostic. Run the optional MCP probe with
python3 proposal-race-probe.py.txt /absolute/path/to/ironrun .
