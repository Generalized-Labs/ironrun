# ironrun — Product / DX & Feature-Gap Audit

**Date:** 2026-06-21
**Auditor:** automated product/DX review
**Repos:** CLI `/Users/kstephenkeehn/ironrun` (Go) · site `/Users/kstephenkeehn/ironrun-site` (`index.html`, live at https://ironrun.dev)
**Build/test status:** `go build ./...` ✅ clean · `go test ./...` ✅ all packages pass · current release **v0.2.0** (GitHub release exists, dated 2026-06-14; tag `v0.2.0` present).

This audit verifies every claim against source. File references use `path:line`.

---

## TL;DR

ironrun is in good shape: the core (policy → provider → runner → redactor) is well-built, the redactor is genuinely streaming/chunk-spanning, CI fork-PR trust is real, and the distribution story (GitHub release + curl installer + manually-maintained Homebrew formula) actually works end-to-end. The biggest issues are two **first-run correctness bugs** (`ironrun init` writes the Claude Code MCP config to a path Claude Code does not read; the README's Codex command uses a non-existent flag syntax) and a **handful of honesty gaps** (chiefly: the site claims Vault support that the code does not have, and `validate` is sold as a health check but only parses YAML). None of the honesty gaps are dishonest about the *security* mechanism — they're about provider breadth and setup polish.

---

## P0 — first-run is broken / a documented path doesn't work

### P0-1 — `ironrun init` writes the Claude Code MCP config to the wrong path → Claude Code never loads ironrun
**Rationale:** `init` creates `.claude/mcp.json` (`cmd/ironrun/init.go:44-66`) and prints "Claude Code: uses `.claude/mcp.json` (per-project, already set up)" (`init.go:113`). But Claude Code's project-scoped MCP server file is **`.mcp.json` at the project root** (verified against current Claude Code docs). `.claude/` holds `settings.json`, not the project MCP server list. Net effect: for the flagship "just `ironrun init` and done" flow on the flagship agent (Claude Code), the MCP server is **not** registered — the user runs `init`, sees green checkmarks, starts `claude`, and `run_sealed` is absent. This is the single highest-impact bug in the product.
**Fix:** write `.mcp.json` at repo root (Claude's documented project scope). Optionally also support `.claude/settings.json` `mcpServers`/`enabledMcpjsonServers` if a stricter scope is wanted. Update the closing summary text and README §Quickstart accordingly.
**Effort:** S · **Files:** `cmd/ironrun/init.go:44-66,113`; `README.md:125`

### P0-2 — README's `codex mcp add` command uses flags that don't exist (and contradicts the code)
**Rationale:** README §"Using with Codex" (`README.md:180`) tells users to run `codex mcp add ironrun --command ironrun --args mcp`. The actual Codex CLI (and ironrun's own `init`) use the `--` passthrough form: `codex mcp add ironrun -- ironrun mcp` (`cmd/ironrun/init.go:127,139,143`). The README command will error for anyone who copy-pastes it. The README and the code disagree with each other on the same command.
**Fix:** change README:180 to `codex mcp add ironrun -- ironrun mcp` to match `init.go`.
**Effort:** S · **Files:** `README.md:180`; cross-ref `cmd/ironrun/init.go:139`

---

## P1 — high-value features / correctness / honesty

### P1-1 — Add a real `ironrun doctor` (preflight) command
**Rationale:** Today `validate` only parses YAML and lists commands (`cmd/ironrun/main.go:115-136`) — it does **not** check provider auth, binary existence, or redaction. Yet README §Troubleshooting (`README.md:435-436`) tells users to "Run `ironrun validate` first" to debug `secret resolution failed`, which `validate` cannot diagnose. A `doctor` that (a) loads the policy, (b) checks each `argv[0]` resolves on PATH (`exec.LookPath`, the runner already does this at `internal/runner/runner.go:62`), (c) checks the provider CLI is installed + authenticated (`op account list` / `doppler whoami` / `infisical whoami`), and (d) does a **dry-run redaction self-test** (resolve one secret, confirm a sample string is redacted, never print the value) would turn the #1 support question ("why doesn't my secret resolve?") into a one-command answer. This is the highest-value *new* feature.
**Effort:** M · **Files:** new `cmd/ironrun/doctor.go`; reuse `internal/provider`, `internal/runner` (`LookPath`), `internal/redact`

### P1-2 — No HashiCorp Vault provider, but it's advertised (see Honesty Gap H-1); add Vault + cloud secret managers
**Rationale:** Provider set is `1password/op, doppler, infisical, env, environment, envfile, passthrough` (`internal/provider/provider.go:42-55`); a test pins that `New("vault")` **errors** (`internal/provider/provider_test.go:36`). The site and FAQ explicitly list Vault (Honesty Gap H-1). Beyond closing the honesty gap, Vault + the three cloud managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) are what enterprise/CI users expect. The provider interface is tiny (`Resolve(ref) (string,error)` + `Name()`, `provider.go:15-20`) and the existing CLI-wrapping providers (`doppler`, `infisical`) are a copy-paste template — a Vault provider shelling out to `vault kv get -field=… <path>` is ~40 lines and mirrors the doppler impl almost exactly.
- **Vault (CLI-wrapped):** S–M — mirror `dopplerProvider` (`provider.go:115-153`), ref form `vault://mount/path#field`. Removes the honesty gap. **Do this one.**
- **AWS / GCP / Azure (SDK or CLI):** M each. CLI-wrapped (`aws secretsmanager get-secret-value`, `gcloud secrets versions access`, `az keyvault secret show`) keeps the zero-dependency, no-CGO build (matches `.goreleaser.yml:16-17 CGO_ENABLED=0`) and the established "wrap the vendor CLI" pattern. SDK versions add auth flexibility but bloat the binary and the dependency tree. **Recommend CLI-wrapped to start.**
**Value/effort verdict:** Vault is high-value/low-effort (also fixes H-1) → do first. Cloud managers are medium-value/medium-effort → fast-follow, CLI-wrapped, gated behind "is the vendor CLI present."
**Effort:** Vault S–M; each cloud M · **Files:** `internal/provider/provider.go` (add cases at :42-55, add provider structs); `internal/provider/provider_test.go:36` (flip the assertion); docs table `README.md:269-276`

### P1-3 — Provider error paths are effectively untested (provider pkg 50.4% coverage)
**Rationale:** `internal/provider` is 50.4% covered; tests exist for `passthrough`, `env`, `envfile` happy paths, but the `1password`/`doppler`/`infisical` `Resolve` error branches (CLI-missing, not-authed, malformed ref) are **uncovered** because they shell out to real binaries. The auth/error mapping (e.g. `ErrOpAuth` detection by stderr substring, `provider.go:92-94`) is exactly the logic users hit when things break, and it's untested. Inject the `exec` lookup (a package-level `execLookPath`/`execCommand` var, or a `runner func` field) so the missing-CLI and ref-parsing branches can be unit-tested with a fake. The doppler/infisical ref-splitting validation (`provider.go:128-131`, `184`) can be tested today with no exec at all.
**Effort:** M · **Files:** `internal/provider/provider.go:78-205`; `internal/provider/provider_test.go`

### P1-4 — `validate` is sold as a health check but only parses YAML (Honesty Gap H-4) — make the docs honest *or* make `validate` do more
**Rationale:** `validate` parses the policy, checks version/dup-IDs/argv presence (via `policy.Parse`, `internal/policy/policy.go:70-100`) and warns on shell argv (`main.go:127-130`). It never touches the provider, PATH, or secrets. README:435 implies it diagnoses `secret resolution failed`. Either (a) point §Troubleshooting at the new `doctor` (P1-1) and keep `validate` as the pure static check, or (b) fold a `--check-binaries`/`--check-provider` flag into `validate`. Cleanest: `validate` stays static, `doctor` does the live checks, README updated.
**Effort:** S (docs) / M (if merged into validate) · **Files:** `README.md:435-436`; `cmd/ironrun/main.go:115-136`

### P1-5 — `ironrun init` doesn't write agent-rule files for Codex/Cursor, but its own output and the README imply the integration is "done"
**Rationale:** `init` writes `CLAUDE.md` (`init.go:69-93`) and registers MCP for Codex/Cursor, then prints "Codex/Cursor: ... registered/merged above" (`init.go:114-115`). But the redaction guarantee depends on the agent actually *choosing* `run_sealed` over the shell — which is driven by the rule file. `init` never creates `CODEX.md`/`AGENTS.md` or `.cursorrules`/`CURSOR.md`; the README even tells the user to do it manually (`README.md:192-197, 214`). So the "registered above" messaging oversells: MCP is wired, but the behavioral nudge (the thing that makes it work) is missing for two of three agents. Note also: Codex's current rules-file convention is `AGENTS.md`, not `CODEX.md` (README:192).
**Fix:** have `init` also write `AGENTS.md` (Codex/Cursor/most agents read it) and `.cursorrules`, with the same "use run_sealed, don't printenv" body as `CLAUDE.md`. One block, big payoff for the "guardrail actually fires" outcome.
**Effort:** S · **Files:** `cmd/ironrun/init.go:69-93` (generalize), README:192-214

### P1-6 — `run` and `validate` give a bare "policy file not found" with no next step
**Rationale:** Run `ironrun run test` in a repo with no `ironrun.yml` and you get `policy file not found: ironrun.yml` (`internal/policy/policy.go:62`) and exit 1 (`main.go:38-40`). For the most common first error, the message should say "→ run `ironrun init` to create one." Same for an unknown command ID (`policy.go:109` "command %q not found" — could append "run `ironrun validate` to list commands"). Small wording change, removes a dead-end.
**Effort:** S · **Files:** `internal/policy/policy.go:62,109`; or wrap in `cmd/ironrun/main.go:51-58`

---

## P2 — polish, hardening, nice-to-haves

### P2-1 — Re-enable goreleaser Homebrew auto-publish (formula is currently hand-maintained)
**Rationale:** The Homebrew formula **does work today** — `Generalized-Labs/homebrew-tap/Formula/ironrun.rb` exists, is pinned to v0.2.0 with correct SHA256s for all 4 platforms (verified), so `brew install generalized-labs/tap/ironrun` (the site's primary CTA, shown 4× incl. the hero copy-button at `index.html:985,1334,1374,1879`) installs correctly. **Risk:** the goreleaser `brews:` block is entirely commented out (`.goreleaser.yml:85-101`), so the **next** release will ship binaries but leave the formula pinned to 0.2.0 — `brew install` would then fetch a stale version. Uncomment + set `HOMEBREW_TAP_GITHUB_TOKEN` so the formula bumps automatically on release.
**Effort:** S · **Files:** `.goreleaser.yml:85-101`

### P2-2 — `mcp` package shows 0% coverage but is actually tested — fix the coverage signal
**Rationale:** `go test -cover` reports `mcp` at 0.0%, which looks alarming, but `mcp/mcp_test.go` has 6 real tests (`TestMCP_RunSealed_Passthrough`, `TestMCP_ListCommands`, etc.) that exercise the server over a stdio/subprocess harness — so the instrumented binary isn't the one measured. This is a *reporting* gap, not a real test gap; worth a note in CONTRIBUTING so nobody "fixes" it by deleting tests. (Real thin spots are `provider` per P1-3 and the two CLI `cmd/` packages, which are integration-tested via `tests/`.)
**Effort:** S (doc note) · **Files:** `mcp/mcp_test.go`; `CONTRIBUTING.md`

### P2-3 — No `ironrun list` top-level command (must go through `validate` or MCP)
**Rationale:** A human wanting to see runnable command IDs from the shell has to read `validate`'s output or the YAML. A first-class `ironrun list` (mirroring the MCP `list_commands` tool at `mcp/server.go:30-40`) is a 10-line cobra command and a natural ergonomic.
**Effort:** S · **Files:** new subcommand in `cmd/ironrun/main.go`

### P2-4 — `no_network` is best-effort and silent on unsupported platforms
**Rationale:** `applyNetworkIsolation` only does anything on linux/darwin (`internal/runner/runner.go:228-235`); on Windows/other it silently no-ops, so a policy with `no_network: true` runs **with** network and the user is never told. README §"What it does/doesn't protect" is honest that this is best-effort (`README.md:402-409`), but the runner should at least emit a `[ironrun] warning: no_network not enforced on <GOOS>` so the gap is visible at runtime. Also: macOS `sandbox-exec` is deprecated by Apple — worth a tracking note.
**Effort:** S (warning) / L (robust isolation) · **Files:** `internal/runner/runner.go:228-235`, `net_other.go`

### P2-5 — Redactor won't catch base64/url-encoded/JSON-escaped secret forms
**Rationale:** The redactor matches the **literal** secret bytes, longest-first, across chunk boundaries (`internal/redact/redact.go:83-125`) — genuinely solid for the exact value. But a command that prints a secret base64-encoded, URL-encoded, or JSON-string-escaped emits a transformed value the redactor won't match. README's "doesn't protect against" list (`README.md:402-407`) covers deliberate file write-back but not encoding transforms. Either add common-encoding variants at `redact.New` (register `base64(secret)`, `url.QueryEscape(secret)` alongside the raw value) or add the limitation to the README threat list. Low likelihood in normal output, but worth an explicit decision.
**Effort:** M (encodings) / S (doc) · **Files:** `internal/redact/redact.go:35-52`; `README.md:402-407`

### P2-6 — Short secrets / common-substring values can over-redact or be footguns
**Rationale:** Any registered secret value is replaced wherever it appears. A secret that is a short or common string (e.g. a 4-char token, or a password that equals a common word) will redact innocuous output, and `passthrough`/`env:literal` make it easy to register such a value. The runner already warns on empty values (`runner.go:71-77`); a parallel warning for very short secret values (say < 6 bytes) at registration time would catch the worst footguns.
**Effort:** S · **Files:** `internal/runner/runner.go:71-77`

### P2-7 — Policy file mode and provider auth aren't surfaced; `init` writes `ironrun.yml` 0644
**Rationale:** Minor: `init` writes `ironrun.yml` at 0644 (`init.go:38`) which is fine (it holds *references*, not values), and the README correctly steers secrets into `~/.secrets/*.env` at 0600 (`README.md:282-292`). No action needed beyond confirming the example/docs never put real values in `ironrun.yml`. Listed for completeness.
**Effort:** — · **Files:** `cmd/ironrun/init.go:38`

---

## Honesty gaps (site / README vs. code)

> Each verified against source. Severity: 🔴 = claims a capability that doesn't exist; 🟡 = misleading/overstated; ⚪ = minor/cosmetic.

### H-1 🔴 — Site claims HashiCorp **Vault** support; there is no Vault provider
- **Claim:** `index.html:1238` — "ironrun pulls from **1Password, Doppler, Infisical, or Vault** at exec time". Repeated `index.html:1262` (FAQ: "pulls from 1Password, Doppler, Infisical, or **Vault**").
- **Reality:** `internal/provider/provider.go:42-55` supports `1password/op, doppler, infisical, env, envfile, passthrough` — **no Vault**. `internal/provider/provider_test.go:36` explicitly asserts `New("vault")` returns an error.
- **Fix:** either build the Vault provider (P1-2, recommended — small) or remove "Vault" from `index.html:1238,1262`.

### H-2 🟡 — README "Using with Codex" command is wrong (flags don't exist)
- **Claim:** `README.md:180` — `codex mcp add ironrun --command ironrun --args mcp`.
- **Reality:** Codex uses `codex mcp add <name> -- <command> [args...]`; ironrun's own `init` uses the `--` form (`cmd/ironrun/init.go:139`). The README flags will error.
- **Fix:** `codex mcp add ironrun -- ironrun mcp`. (Also P0-2.)

### H-3 🟡 — `ironrun init` / README claim Claude Code is "set up", but it writes the wrong file
- **Claim:** `README.md:125` "`.claude/mcp.json` — wires Claude Code up to ironrun"; `init` prints "Claude Code: uses `.claude/mcp.json` (per-project, already set up)" (`cmd/ironrun/init.go:113`).
- **Reality:** Claude Code reads project MCP servers from **`.mcp.json` at the repo root**, not `.claude/mcp.json` (verified vs. current Claude Code MCP docs). The written file is ignored → Claude Code does not get `run_sealed`.
- **Fix:** P0-1 (write `.mcp.json`).

### H-4 🟡 — Docs imply `validate` checks secret resolution; it only parses YAML
- **Claim:** `README.md:435-436` — for `secret resolution failed`, "Run `ironrun validate` first — it checks that your policy file is valid."
- **Reality:** `validate` (`cmd/ironrun/main.go:115-136`) parses YAML and lists commands; it never contacts the provider or resolves a secret. It cannot diagnose a resolution failure.
- **Fix:** P1-1 (`doctor`) + repoint the troubleshooting step (P1-4).

### H-5 ⚪ — README §"Codex" tells users to create `CODEX.md`; the current convention is `AGENTS.md`
- **Claim:** `README.md:192` — "add to your project's CODEX.md (equivalent of CLAUDE.md)".
- **Reality:** Codex (and most agents) read `AGENTS.md`. `CODEX.md` is not the standard file. Not a code bug, but it sends users to a file the agent won't read → the run_sealed nudge silently doesn't apply.
- **Fix:** reference `AGENTS.md` (and tie into P1-5 so `init` writes it).

### H-6 ⚪ — `codex mcp add ironrun --command … --args …` also appears nowhere in code; double-check Codex's flag set
- Same root as H-2; flagged separately only because the README presents *two* Codex setup methods (the wrong CLI flags at `README.md:180` and a correct-looking TOML block at `README.md:185-190`). Keep the TOML, fix the CLI line.

### Things that are accurate (verified — to avoid false alarms)
- **Redaction is real and streaming/chunk-spanning** as the site/README claim (`index.html:1155` "Catches partial leaks across chunks"; impl `internal/redact/redact.go:83-125` holds back `maxLen-1` bytes across writes). ✅
- **Fork-PR / `pull_request_target` secrets are blocked** as the README table states (`README.md:365-370`; impl `internal/runner/runner.go:198-221`, tested `runner_test.go` `TestRun_CIForkPRDenied` / `…PullRequestTarget…`). ✅
- **MCP exposes exactly the three claimed tools** `list_commands`, `run_sealed`, `validate_policy` and none return a secret (`README.md:332-357`; impl `mcp/server.go:30-63`). ✅
- **Dangerous env vars (`LD_PRELOAD`, `DYLD_*`, `BASH_ENV`, …) are stripped** from the child env (`internal/runner/runner.go:154-167`) — not advertised, but a real hardening win worth surfacing on the site. ✅
- **`brew install generalized-labs/tap/ironrun` works** — formula present and correctly pinned to v0.2.0 (homebrew-tap `Formula/ironrun.rb`). ✅
- **`go install …@latest` and the curl installer work** — v0.2.0 release with all platform tarballs + `checksums.txt` exists; `install.sh` verifies the checksum (`install.sh:51-71`). ✅
- **Version reporting is correct** — `go install @vX.Y.Z` recovers the version from build info even without goreleaser ldflags (`internal/buildinfo/buildinfo.go:24-31`), matching README:108-110. ✅

---

## Test-coverage summary (from `go test ./... -cover`)

| Package | Coverage | Note |
|---|---|---|
| `internal/redact` | 95.9% | Excellent — 58 tests incl. edge/timing/bench |
| `internal/runner` | 78.7% | Good — CI trust, exfil, maxbytes, timeout all covered |
| `internal/policy` | 75.8% | Good |
| `action` | 67.3% | OK |
| `internal/provider` | **50.4%** | **Thin** — CLI provider error paths untested (P1-3) |
| `mcp` | 0.0% reported | **Misleading** — 6 real tests via stdio harness (P2-2) |
| `cmd/ironrun`, `cmd/ironrun-action` | 0.0% | Integration-tested via `tests/` (`tests/cli_test.go`, `tests/init_test.go`, 21 tests) |
| `internal/buildinfo` | 0.0% | Trivial |

**Biggest real gap:** provider error/auth paths (P1-3). Everything security-critical (redaction, CI trust, exfiltration) is well covered.

---

## Suggested sequencing

1. **P0-1** (`init` → `.mcp.json`) and **P0-2** (README Codex flag) — same afternoon, unblocks the flagship flow. (S+S)
2. **P1-2 Vault provider** — closes H-1, ~40 lines, mirrors doppler. (S–M)
3. **P1-1 `doctor`** — turns the #1 support question into one command; closes H-4. (M)
4. **P1-5** (`init` writes `AGENTS.md`/`.cursorrules`) + **H-5** — makes the guardrail actually fire on Codex/Cursor. (S)
5. **P1-3** provider error-path tests + **P1-6** actionable not-found messages. (M+S)
6. **P2-1** re-enable goreleaser brew auto-publish before the next tag. (S)
7. Cloud secret managers (AWS/GCP/Azure, CLI-wrapped) as demand appears. (M each)
