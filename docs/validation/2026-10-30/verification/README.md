# Fresh launch verification — October 30, 2026

Tested clean source: `07eb2c49c6ed32e7a67eeb05af5c3a70add1f0ef`.
All 182 Go/module input files and README stayed unchanged through every phase.
The exact input hashes, commands, timestamps, tool hashes and raw logs are retained.
No repository source, configuration, evidence archive or Git state was changed.

| Check | Result |
| --- | --- |
| `go test -race -count=1 ./...` | Passed; 34.66 s; synthetic namespace tests outside the additional agent filesystem sandbox, Ironrun containment retained |
| `go vet ./...` | Passed |
| Pinned Staticcheck 0.8.2 | Passed |
| Diagnostic CLI build, help and version | Passed; no vault/native-store workflow claimed |
| Release regressions | 11 passed; fixture verifier, not real Sigstore cryptography |
| Node 24.19.0 launcher tests | 19 passed, zero failures/skips |
| GitHub current-head checks | 14 success, one optional Macroscope skipped; includes Linux/macOS race, Node20/22/24, govulncheck, CodeQL, fuzz and dogfood |

A local vulnerability scan was not repeated: no govulncheck binary or module
cache is present. The actual current-head CI vulnerability check was observed
successful and is linked in `github-checks.json`.

These results support the automated proof of the reviewed changes. They do not
establish native Keychain/Secret Service, human Mac/other-agent-host onboarding,
actual signed tagged installation, npm bootstrap, Homebrew/Apple migration,
real-model judgment or sustained everyday use. Consult the repository's
`docs/LAUNCH_READINESS.md`, `HOST_E2E.md`, and release checklist before tagging or
publishing. No merge, release, registry publication or deployment is performed
by this verification.

`ironrun-current-check` is a local diagnostic binary; its digest is in
`cli-smoke.json`. It, caches and temporary state are excluded from the compact
artifact manifest. The driver uses absolute workspace paths that need adaptation
elsewhere. `artifact-manifest.json` excludes itself.
