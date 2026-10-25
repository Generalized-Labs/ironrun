# Setup Correctness Implementation Plan

> **For agentic workers:** Use subagent-driven development for the two independent
> repairs, then review the whole diff. Steps below use red/green verification.

**Goal:** Preserve client settings and truthfully report setup and approval state.

**Architecture:** Repair the existing CLI registration helpers and MCP response.
Keep client outcomes local to setup; leave grants, leases, and waiting unchanged.

**Tech Stack:** Existing Go/Cobra CLI, JSON client configuration, access manager.

**Spec:** [Setup correctness design](../specs/2026-10-24-setup-correctness-design.md)

## Global constraints

- Go 1.26.10; no new product dependencies.
- Synthetic credential-free fixtures; no actual user client config or keychain.
- Preserve existing/client-custom settings; no automatic replacement on error.
- Keep authorization timing and permission semantics unchanged.
- Work in the existing isolated `/workspace/ironrun-product-review` worktree.

## Review focus

Unreadable-but-writable files must survive; null or wrong-shaped JSON must not
panic or silently discard settings; custom/disabled entries need truthful
status; inspection errors cannot imply absence; reused requests retain expiry.

## Task 1: Safe registration and truthful summary

Files: `cmd/ironrun/init.go`, a small registration helper if needed,
`cmd/ironrun/*registration*_test.go`, and `tests/init_test.go` as appropriate.

- [x] Add behavior regressions for preservation, malformed shape, per-client
  success/failure/unavailable/custom state, and removal of automatic-use claims.
- [x] Run the tests against current code and record expected failures.
- [x] Repair file reads/merges and propagate registration outcomes to the summary.
  Use Codex structured output; leave unrecognized existing entries unchanged.
- [x] Run new and existing setup tests under the race detector; inspect the diff.

## Task 2: Actual pending-request deadline

Files: `mcp/server.go`, `mcp/access_test.go`.

- [x] Assert that the workspace response includes the persisted `ExpiresAt`
  deadline and distinguishes `RequestedTTL` access duration, including reuse.
- [x] Observe the existing incorrect two-hour-expiry response fail the test.
- [x] Format the stored expiry and requested duration without changing state.
- [x] Run focused MCP/access race tests and inspect the diff.

## Task 3: Whole-change verification and delivery

- [x] Independently review both repairs, resolving concrete findings.
- [x] Replay setup with REA; verify preserved configuration and truthful output.
- [x] Run the full race suite, vet, and four-platform release-style builds.
- [x] Record exact source/tool identities, raw results, and remaining host gates.

Delivery: update [draft PR #16](https://github.com/Generalized-Labs/ironrun/pull/16)
through the GitHub connector and verify its new-head CI before reporting delivery.
The PR records the final commit and remote check results; this local plan does
not predict those outcomes. Evidence is in `docs/validation/2026-10-24/`.
