# Setup and approval correctness repairs

The maintainer asked to continue repairing and testing Ironrun for launch after
the deeper review. These repairs restore the existing setup and approval
contracts; they add no authorization mode or automatic configuration replacement.

## Intent and constraints

Preserve existing client configuration, report what setup actually achieved,
and distinguish the pending request's review deadline from a future grant's
duration. Keep the current CLI, project-file generation, optional client
registration, and authorization semantics. Use synthetic fixtures only.

## Approach

Repair the existing registration and message paths. A documentation-only warning
would leave the reproduced configuration loss in place; a new onboarding wizard
would add unrelated behavior. The existing-flow repair is the bounded approach
selected for this continuation under the maintainer's repair request.

- Create a client configuration only when the file is absent. Any other read
  error, invalid JSON, or invalid object shape leaves existing bytes untouched.
- Preserve other servers and settings when merging. Preserve conflicting or
  custom existing Ironrun entries and report that they need inspection.
- Track per-client registration outcomes. Distinguish configuration written or
  recognized from missing CLI, failure, and preserved/unverified configuration.
  Never infer that the host has connected or will invoke tools automatically.
- Use structured Codex MCP inspection instead of substring matching. A failed
  inspection must not justify overwriting an existing registration.
- Retain core setup's existing exit and file-generation behavior for optional
  client issues; make partial results and repair instructions visible.
- Display the persisted request's actual expiry and its separately requested
  access duration. Deduplication must not imply a new review window.

## Verification

Use failing regressions before implementation, including unreadable-but-writable
configuration as a non-root user, malformed/null/wrong-shaped JSON, unrelated
settings, existing/custom/disabled registrations, missing/failed Codex, and
deduplicated request expiry. Replay synthetic setup with REA and compare retained
configuration bytes. Run focused and complete race tests, vet, and normal builds.

Paper corrections are a separate workstream: align claims with source, verify
citations, fix prose/title capitalization, synchronize metadata, and rebuild
the PDF and source bundle. No release, merge, tag, or submission is authorized by
this design; the existing draft PR remains the delivery target.
