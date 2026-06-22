# ironrun Security Audit — Sealing & Redaction Guarantee

**Date:** 2026-06-21
**Auditor:** Adversarial code review (defensive, authorized)
**Scope:** `internal/redact`, `internal/runner`, `internal/provider`, `internal/policy`, `mcp/`, `cmd/ironrun/`, `action/`
**Method:** Read every source file against current code; `go build ./...` (clean) and `go test ./... -race` (all green); constructed concrete repros through the real runner and redactor for every suspected leak; distinguished exploitable from theoretical and from already-acknowledged-out-of-scope.

---

## Verdict

**The core literal-value sealing + redaction guarantee holds.** Resolved secret values are injected only into the child process environment, never placed in argv, temp files, command echo, error messages, MCP responses, or GHA outputs. The streaming redactor correctly catches literal secret values across arbitrary Write/chunk boundaries, byte-by-byte writes, Unicode/emoji splits, overlapping secrets, multiline/null/tab/special-char secrets, and the maxBytes cap — verified by an extensive existing test suite *and* by additional adversarial repros I wrote during this audit (all held).

**Every real finding below is a *transformation* or *threat-model boundary* issue, not a flaw in the literal redactor.** If a policy-authorized binary emits the secret in any encoded/transformed form (base64, hex, ANSI-broken, etc.), the literal redactor cannot catch it. Most of this is already disclosed as out-of-scope in `SECURITY.md` ("Network exfiltration by approved binary", "Secrets written to disk by child"). The findings sharpen and rank those boundaries and surface a couple of hardening gaps.

No **Critical** finding. The sealing guarantee, *as scoped in SECURITY.md*, is sound.

---

## Findings

### HIGH-1 — Redaction is literal-bytes only: any encoded/transformed emission of the secret bypasses it
**Files:** `internal/redact/redact.go:99-114` (match is exact-byte `hasPrefix`), `internal/runner/runner.go:71-93` (only the raw resolved value is registered).

**Leak path:** The redactor matches the *exact byte sequence* of the resolved secret. A policy-authorized command that emits a transform of the value defeats it entirely. Confirmed repros (run through the real `runner.Run`):

- **base64:** secret `ironrun-canary-xK9mQ2pR` → command emits `aXJvbnJ1bi1jYW5hcnkteEs5bVEycFI=`, which passes through untouched and the agent decodes it back to the exact secret.
- **ANSI-interleaved:** a program emitting `\x1b[32mSEC\x1b[0mRET` renders as `SECRET` in any terminal but is not matched, because the literal bytes differ.

Hex, URL-encoding, gzip, reversed, char-substituted, and chunked-across-files forms are all equally invisible to a literal matcher.

**Exploitability:** Bounded by the policy. The agent cannot run an arbitrary `base64 <(printenv SECRET)` because argv is pinned by policy and the MCP surface only accepts a `command_id` (see "What holds", below). The realistic threat is a *policy-authorized binary that itself emits an encoded form* — e.g. a deploy script that base64s a config blob, a tool that logs a JWT, or a compromised/typo-squatted authorized binary. `SECURITY.md` already lists "Network exfiltration by approved binary" as out-of-scope; this is the **stdout** analog and should be stated just as explicitly.

**Fix:**
1. Document explicitly in `SECURITY.md` that redaction is literal-only and does **not** cover encoded/transformed emissions — the same trust boundary as the network case. This is the most important fix: it converts a silent gap into a stated limitation.
2. Optionally, register common encodings of each secret as additional redaction targets at `runner.go:71-78`: base64 (std + url, with/without padding), hex (upper/lower), and percent-encoding of the raw value. This catches the most common accidental-leak shapes (a tool that base64s a secret) at near-zero cost. It cannot be complete (no defense covers all transforms) but it removes the easy ones.
3. ANSI specifically: consider stripping ANSI CSI sequences from a *copy* used only for matching, or document it. Lower priority than (1).

---

### MEDIUM-1 — Very short resolved secret values cause silent, unbounded false-positive redaction (integrity/availability, and a foot-gun that masks real leaks)
**File:** `internal/redact/redact.go:35-52` (no minimum-length guard); confirmed via runner.

**Leak path (inverse):** A secret that resolves to a 1–2 character value (misconfigured provider, a literal like `0`/`a`, a boolean flag stored as a secret) turns *all* matching characters in output into `[REDACTED]`. Confirmed: a 1-char secret `a` rewrote `banana` → `b[REDACTED]n[REDACTED]n[REDACTED]`. This corrupts the agent's view of output and can hide genuine errors. It is not a secret *leak*, but it is a correctness/robustness defect and an attacker who can influence a resolved value could weaponize it for output-poisoning.

**Fix:** In `redact.New`/`AddSecret`, skip (with a warning to stderr, like the empty-secret warning at `runner.go:74`) any secret shorter than a threshold (e.g. < 4 bytes), OR have the runner refuse to inject a credential whose resolved value is implausibly short. At minimum, log a warning so the operator notices. Mirror the existing empty-value warning pattern.

---

### MEDIUM-2 — macOS network-isolation sandbox profile is permissive on the filesystem; combined with literal-only redaction it widens the approved-binary exfil surface
**File:** `internal/runner/runner.go:237-253` (`applyDarwinNetworkIsolation`).

**Observation:** The Seatbelt profile is `(deny default)` then `(allow file-read*)(allow file-write*)`. Network is denied (good, that is the feature's job), but the child retains full filesystem read/write. A `no_network: true` deploy command can still write the secret (or an encoded form) to any file the user can write, where a later non-sealed agent action reads it back. This is consistent with SECURITY.md's "Secrets written to disk by child = Not prevented", so it is a documentation/expectations issue rather than a new break — but the `no_network` feature gives a false sense of containment if users assume "isolated."

**Fix:** Document that `no_network` blocks only network, not disk. If stronger containment is ever desired, the Seatbelt profile could restrict `file-write*` to a temp scratch dir. Low urgency; primarily a docs fix.

---

### MEDIUM-3 — `op` (1Password) provider error path returns raw CLI stderr; doppler/infisical likewise — verify no value echo
**Files:** `internal/provider/provider.go:95` (`op`), `:148` (doppler), `:201` (infisical).

**Observation:** On a failed resolve, the providers wrap the CLI's stderr into the returned error. For `op read`, doppler `secrets get`, and infisical `secrets get`, a *failed* resolution has not produced a value, so the value cannot appear in stderr. The CLIs are invoked with `--plain`/`--no-newline`/`--silent`/`--no-read-env`, which suppress decoration. In `mcp/server.go:85-89` the resolve error is deliberately *not* forwarded to the agent (returns a generic "secret resolution failed"), so even if a CLI misbehaved the agent would not see it. In `cmd/ironrun/main.go:67` and `action/action.go:63-65` the error is shown to the human/CI operator, which is acceptable.

**Status:** No leak found. Flagged as **defense-in-depth**: a future provider CLI (or a future flag regression) could conceivably echo the looked-up value into stderr on certain errors. **Fix (hardening):** never interpolate raw provider stderr into errors that can reach a non-operator surface; the MCP path already does the right thing — keep it that way and add a regression test asserting the MCP resolve-error response never contains a known value.

---

### LOW-1 — `AddSecret` after data has been emitted leaks (known, documented, and not reachable in production)
**Files:** `internal/redact/redact.go:155-170`; documented by the authors in `redact_addsecret_timing_test.go` and `TestAddSecretAlreadyInBuffer`.

**Observation:** If `AddSecret` is called after output containing the (then-unregistered) value has already passed the hold window, that occurrence leaks. **However, `AddSecret` has no production caller** — verified: the only references are the function definition and tests. The runner registers *all* secret values up front at `runner.go:71-93` before any child output exists. So this is unreachable in the live product.

**Fix:** Keep `AddSecret` for tests only, or add a doc comment that it must only be called before the writer sees any data. No runtime change needed. If `AddSecret` is ever wired into a streaming path, this becomes HIGH.

---

### LOW-2 — `maxBytes` cap can truncate mid-secret, but never *under*-redacts; partial leak is not possible
**Files:** `internal/redact/redact.go:128-144`, tests `TestMaxOutputCutsRedaction`/`TestAudit_MaxOutPartialSecret`.

**Observation:** When output is capped, the cap is applied to *already-redacted* bytes in `emit`. A secret is replaced by `[REDACTED]` *before* the cap is considered, so truncation can cut the placeholder (`[REDA`) but can never expose secret bytes. Verified: a 12-byte cap with secret `MYSECRETKEY` produced `hello [REDAC` — no secret substring. **No fix needed.** Noted because it is an obvious place to look for a partial-leak and it is correctly handled.

---

### LOW-3 — `Truncated` flag is per-stream and uses `>=`, a cosmetic reporting imprecision (no security impact)
**File:** `internal/runner/runner.go:148`.

`Truncated` is true if *either* stream hit its own `maxBytes` cap (each stream gets an independent cap, not a combined budget). This is a reporting nuance, not a leak. No fix required; mention in docs if combined budgeting is ever expected.

---

## What holds (the evidence that convinced me the guarantee is sound)

1. **Injection ≡ redaction set.** `runner.go:71-104` builds the redactor's secret list and the child env from the *same* `opts.Secrets` map. The exact bytes injected are the exact bytes redacted — there is no path where a value is injected but not registered for redaction (empty values are skipped *and* warned, `runner.go:72-78`).

2. **Secrets never touch argv.** argv comes solely from the policy (`policy.Command.Argv`); secrets are env-only (`buildEnv`, `runner.go:183-196`). The MCP tool accepts only `command_id` (`mcp/server.go:49-53`), so an agent cannot append args or inject a transform command. `AuthorizeArgv` enforces exact-match where used.

3. **MCP responses are redacted and resolve-errors are sanitized.** `run_sealed` streams *live* output to `os.Stderr` (not agent-visible, `server.go:92-93`) and returns only `res.Stdout`/`res.Stderr`, which are the redacted MultiWriter sinks (`runner.go:92-93, 145-146`). Resolve failures return a generic message, not the failing ref or value (`server.go:87-89`). Verified end-to-end by `tests/exfiltration_test.go` (env/printenv/`/proc/self/environ`/large-output-at-boundary all redacted in both live stream and `Result` struct).

4. **Flush always runs before return.** `stdoutW.Flush()/stderrW.Flush()` at `runner.go:127-128` execute before every error branch (timeout, exit-error, exec-error). `c.Run()` guarantees the exec copy goroutines have finished before it returns, so no buffered secret bytes are dropped or raced. Confirmed `go test -race` clean on `internal/redact` and `internal/runner`.

5. **The literal streaming redactor is genuinely robust.** Existing tests plus my adversarial additions all hold: split at every byte boundary, three-chunk split, byte-by-byte, long-secret (8 KB) split, 10 000 occurrences, Unicode/emoji mid-character splits, overlapping/prefix/nested secrets (longest-first matching), null/tab/newline/regex-special secrets, repeated-first-byte and almost-match pathological inputs, the long-maxLen/short-secret-tail boundary case, and placeholder-as-secret. The `hold = maxLen-1` window plus longest-first matching is correct.

6. **CI trust gate fails closed.** Fork `pull_request` and `pull_request_target` are denied before any secret resolution (`runner.go:198-221`), tested in `runner_test.go`.

7. **Shell execution is denied** at argv level before exec (`runner.go:52-55`, `policy.IsShellString`), closing `sh -c "echo $SECRET"` style expansion. Tested in `exfiltration_test.go:179`.

8. **Init/action write no secrets.** `init.go` writes only env-var *names* (`detectEnvVars` returns keys, never values, `init.go:290-325`). `action.go` GHA outputs are only `exit_code`/`duration_ms`/`truncated` (`action.go:79-85`) — never a value.

---

## Prioritized fix list

| # | Sev | One-line | Where | Fix |
|---|-----|----------|-------|-----|
| HIGH-1 | High | Literal-only redaction; encoded forms (base64/hex/ANSI) bypass it | `redact.go:99-114`, `runner.go:71-78` | Document the limit in SECURITY.md (primary); optionally also register base64/hex/url-encoded forms of each secret |
| MEDIUM-1 | Med | Ultra-short resolved value silently mass-redacts output | `redact.go:35-52` | Warn + skip secrets shorter than ~4 bytes (mirror empty-value warning) |
| MEDIUM-2 | Med | macOS `no_network` profile still allows full disk write | `runner.go:237-253` | Document "network-only"; optionally restrict `file-write*` |
| MEDIUM-3 | Med | Provider error path returns raw CLI stderr (no leak found) | `provider.go:95,148,201` | Keep MCP sanitization; add regression test asserting no value in resolve-error |
| LOW-1 | Low | `AddSecret`-after-emit leaks (no production caller) | `redact.go:155-170` | Doc-only: must be called before any data; keep test-only |
| LOW-2 | Low | maxBytes can cut placeholder but never under-redacts (correct) | `redact.go:128-144` | None |
| LOW-3 | Low | `Truncated` is per-stream, `>=` — cosmetic | `runner.go:148` | None / doc |
