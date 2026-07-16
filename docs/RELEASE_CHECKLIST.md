# Ironrun v1.0 release checklist

Ironrun v1.0 is released only from a clean, merged `main` commit. A passing pull
request is necessary, but it is not the release decision by itself.

## Automated gates

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] `staticcheck ./...`
- [ ] `govulncheck ./...`
- [ ] Fuzz-smoke policy, dotenv, capsule, metadata, RPC, and audit parsers
- [ ] Build macOS and Linux for amd64 and arm64
- [ ] Build and smoke-test the Windows amd64 beta
- [ ] Produce a GoReleaser snapshot and verify every archive and checksum
- [ ] Run installer tampering and missing-checksum tests
- [ ] Run the npm launcher tests on Node 20, 22, and 24
- [ ] Pack the npm package and install the tarball in an isolated project
- [ ] Verify cold cache, warm cache, corrupt cache, concurrent launch, offline,
      proxy, read-only cache, signal forwarding, non-TTY, and paths with spaces
- [ ] Scan policies, registries, metadata, logs, snapshots, caches, artifacts,
      fixtures, and Git history for test-secret literals and encoded forms
- [ ] Verify SBOMs, checksums, npm provenance, and Sigstore bundles
- [ ] OpenSSF Scorecard and repository security checks pass

## Required product proofs

- [ ] A fresh project reaches its first sealed command in under two minutes
- [ ] A secret can be added in under 20 seconds
- [ ] A waiting request appears locally in under 250 ms
- [ ] A user can make an informed approval in under 15 seconds
- [ ] A missing secret is entered once and the waiting MCP call resumes in under
      45 seconds, without an IDE, restart, manual retry, or chat handoff
- [ ] Environment and JSON/PEM file secrets are redacted in literal, base64,
      hex, and URL-encoded output
- [ ] Temporary file secrets are removed after success, error, timeout,
      cancellation, and validated crash recovery
- [ ] Leases expire and revoke immediately; authorization remains pinned to the
      reviewed project, environment, command, and MCP session
- [ ] Version-1 policy migration, rollback, and confirmed cleanup work without
      putting a value in policy, metadata, logs, or migration records
- [ ] The TUI is keyboard-complete at 40x12, 80x24, 160x16, and a large terminal
- [ ] Warm startup is under 500 ms, navigation is under 50 ms, idle CPU is under
      0.5%, and there is no idle redraw loop

## Human and platform gates

These gates cannot be inferred from CI or replaced with simulated results.

- [ ] Dogfood five real projects for seven consecutive days without opening an
      IDE only to manage environments
- [ ] Test with 8-12 external developers using Codex, Claude Code, or Cursor
- [ ] At least 8/10 users complete onboarding unaided
- [ ] At least 7/10 users complete the agent approval flow
- [ ] At least five users return within seven days
- [ ] Dogfood `v1.0.0-rc.1` on macOS amd64/arm64 and Ubuntu amd64/arm64
- [ ] Confirm the Windows amd64 beta smoke suite
- [ ] Resolve every critical and high-severity issue

## Publication gates

- [ ] The scoped npm package and custom Homebrew tap are controlled by the
      project maintainers with 2FA and least-privilege publishing access
- [ ] The tag, Go version, npm version, cask version, manifest, checksums, and
      release notes all identify the same commit and version
- [ ] Publish `v1.0.0-rc.1` under the npm `next` tag and inspect staged artifacts
- [ ] Promote the identical verified commit to `v1.0.0`, npm `latest`, and the
      Homebrew tap only after every gate above passes

Do not tag or describe a build as GA while any required gate is incomplete.
