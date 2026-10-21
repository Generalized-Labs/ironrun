# Final local validation — October 21, 2026

Base commit: 8e3c354d95db18d91af029c9081b4da4825d2680, plus the source changes recorded in this pull request. Go 1.26.9; Linux amd64. Credentials and real secrets were not used.

- `go test -race ./...`: passed. Linux namespace tests ran outside the filesystem sandbox; state and caches were under temporary paths.
- `go vet ./...` and `staticcheck ./...`: passed. Staticcheck initially required its cache redirected from the read-only home directory.
- `go test ./internal/redact -run '^$' -fuzz '^FuzzRedact$' -fuzztime=10s -parallel=2`: passed; 22,581 executions over 11 seconds. Checks chunked/batch equality for fixed patterns in addition to the existing leakage invariants.
- `python3 -m unittest discover -s tests -p release_test.py`: 11 passed. Synthetic download/verifier fixtures exercise control flow, not real Sigstore crypto.
- Latest unchanged npm launcher suite: 13 tests passed on Node 20.20.2, 22.23.3, 24.19.0; raw outputs are in ../2026-10-20/.
- `goreleaser release --snapshot --clean --skip=publish,sign,sbom,before`: passed; four Linux/macOS x86_64/arm64 archives. Checksums verified and Linux amd64 `version` ran. No actual release, signing, SBOM, or target-platform execution claim. The legacy Homebrew stanza still emits a deprecation warning; `goreleaser check` remains nonzero until migration.
- Final manuscript builds to 14 pages. A tracked-PDF/no-bibliography fixture reproduced the old `make arxiv` failure; fixed make rule builds the bundle. Extracted source bundle compiles independently with the same local TeX packages. Metadata abstract: 1,905 ASCII characters. Minor monospace italic font fallback remains; no undefined citations or overfull boxes in final build.
- Gap-scan probe: 64 KB newline-only synthetic output with a whitespace-leading registered value improved from 884 ms to 7 ms in one run. Independent rerun was 3 ms. Timing is diagnostic; no stable hardware benchmark claim. The probe source is included for reproduction.
- `git diff --check`: passed.

Final stdout/stderr flush-failure tests and hyphenated prerelease installation tests failed before their fixes and pass afterward. Independent runtime and release reviews found no remaining blocker in those specific repairs.

Open gates: live signed-release verification, real macOS/ARM/proxy/read-only-cache paths, registry/account bootstrap, external-user validation, and supporting historical self-audit/performance/false-positive/RQ4 records. Automated tests do not establish perfect correctness or certify security.

Final `go run ./paper/eval --only leak` rerun again produced 28/126 threshold cases (raw `current-leak.txt`). The earlier paired baseline remains in ../2026-10-20/.

To run the gap-scan probe, copy `gap-scan-probe.go.txt` to `main.go` in a temporary module named `github.com/generalized-labs/ironrun/reviewprobe`. Require `github.com/generalized-labs/ironrun v0.0.0` and replace that dependency with the absolute checkout path, then `go run .`. Do not treat shared-host elapsed times as a stable throughput measurement.
