# Troubleshooting

Common failure modes and how to fix them. For install and signature
verification problems, see [INSTALL.md](INSTALL.md). For "is this platform
supported" questions, see [windows.md](windows.md).

## Quick diagnosis first

Most problems are answered in seconds by:

```bash
ironrun doctor    # read-only checks: policy, provider, redaction, PATH
ironrun validate  # does ironrun.yml parse? which commands are defined?
ironrun lint      # security checks over the policy file
```

If an error message already names the fix (backticked `ironrun ...` command),
run that first — the CLI appends remediation hints to the errors it knows.

## Install / upgrade

| Symptom | Fix |
|---|---|
| `install.sh` aborts on checksum or Sigstore verification | Do not bypass it. Check your clock (certificate validity is time-sensitive) and confirm you downloaded a real GitHub release asset, not a re-hosted copy. See [INSTALL.md](INSTALL.md#manual-verification). |
| `no checksum entry for …` | The release is incomplete; do not install from it. Report it as a release bug. |
| `cosign not found and no network` | First-run signature verification needs the network. Fall back to the manual `sha256sum -c` check against a `checksums.txt` you obtained and verified separately. |
| `ironrun: command not found` after install | The installer targets `/usr/local/bin` (or `~/.local/bin` without sudo). Check `echo $PATH` and `ls /usr/local/bin/ironrun ~/.local/bin/ironrun`. Re-run with `--dir` to choose the location explicitly. |

## Policy errors

**`Error: policy file not found: ironrun.yml`** — you're outside a project
directory, or the project was never set up. Fix: `ironrun init` in the project
root, or pass the policy explicitly: `ironrun --policy PATH <command>`.

**`Error: policy file malformed: …`** — the YAML has a structural problem; the
message names the offending field. Fix: `ironrun validate --policy PATH` shows
exactly what parsed, then fix the file. `ironrun lint` catches security
misconfigurations (not syntax).

**`Error: command "X" not found in policy`** — the ID isn't in this project's
`commands:` allowlist. Fix: `ironrun validate` lists the allowed IDs. Agents
can only run IDs declared there — that's the point.

**`unknown command "statuz"`** — the CLI suggests the closest match
(`Did you mean \`ironrun status\`?`). It never auto-runs the suggestion.

## Secrets and environments

**`no active environment is selected`** — create one, then store the value:

```bash
ironrun new NAME
ironrun env set KEY   # masked prompt; values are never flags
```

**`secret "X" not found in …`** (provider) — the secret isn't stored yet.
`ironrun env set X` stores it in the active environment.

**`secret resolution failed: …`** — ironrun.yml references a secret the
environment doesn't have. Either store it (`ironrun env set KEY`) or remove it
from the command's `secrets:` list.

**`provider not configured`** — run `ironrun doctor`. On a fresh machine,
`ironrun init` sets up the local encrypted vault.

**Value still visible in output?** — first, confirm the value is actually
managed: `ironrun env list` shows key names (never values). Redaction covers
managed values and their encoded variants. If output contains a *different*
string that merely looks secret-like, the post-run entropy scan warns on
stderr — investigate before sharing that output. Values the agent generated
itself (not from the vault) are a known residual risk; rotate them and see
[concepts.md](concepts.md#honest-limits).

## Linux secret storage

On Linux, the encrypted environment store needs the Secret Service:

```text
initialize encrypted environment: native secure storage unavailable on linux: install libsecret secret-tool
```

Install `libsecret-tools` (e.g. `apt install libsecret-tools`) and ensure a
D-Bus session secret service (GNOME Keyring / KWallet) is running. Headless
servers without a secret service can't host the vault — use a machine with
one, or wait for the documented headless story.

## Daemon

```bash
ironrun daemon status    # is the per-user service healthy?
ironrun daemon install   # preview + install the launchd/systemd user unit
```

If `init`'s optional service install fails (e.g. no systemd user bus in a
container), that's fine — the daemon is optional. Re-run
`ironrun daemon install` on the real host later.

## MCP clients

- **Claude Code**: `ironrun init` writes `.mcp.json` at the project root.
  Restart Claude Code after setup; project MCP servers load at session start.
- **Codex**: `init` registers via `codex mcp add` when the `codex` binary is on
  PATH, otherwise it prints the manual command — run it yourself.
- **Cursor**: `init` merges `~/.cursor/mcp.json`. Restart Cursor.
- Verify end-to-end with `ironrun mcp` in a terminal: it should start and wait
  on stdio (Ctrl-C to stop). If a client can't reach it, check the client's
  MCP logs — the server side is the same binary.

## Windows

`ironrun` refuses to run secret-input commands on Windows — loudly, with a
non-zero exit — instead of silently degrading. This is intentional; see
[windows.md](windows.md) for the full list and the rationale.

## Still stuck?

1. `ironrun doctor` output (it's redacted-safe to share — never values).
2. `ironrun version -v` (version, commit, build date).
3. The exact command and full stderr.
4. OS and how you installed (`docs/INSTALL.md` method).

File an issue with those four; skip anything containing a secret value —
rotate it instead.
