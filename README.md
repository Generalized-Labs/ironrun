# ironrun

**Manage project environments in the terminal and let AI agents use secrets without reading them.**

[![CI](https://github.com/generalized-labs/ironrun/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/generalized-labs/ironrun/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/generalized-labs/ironrun)](https://goreportcard.com/report/github.com/generalized-labs/ironrun)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/generalized-labs/ironrun/blob/main/LICENSE)

---

ironrun is a local-first encrypted environment workspace. It gives humans one terminal UI for projects, environments, `.env` imports, and agent access. Trust an agent session once for a project’s `dev` environment, then it can work normally while ironrun injects values only into child processes and strips them back out of output before the agent sees them.

Your tests still get a live `DATABASE_URL`. The agent gets back `exit_code: 0` and `tests passed` — and never the connection string.

---

## Why you might want this

Coding agents (Claude Code, Codex, Cursor, and others) run shell commands on your machine, and those commands can see your environment. Most of the time that's fine. The problem is the small set of commands that *print* the environment:

```bash
printenv                 # dumps every env var, including secrets
cat .env                 # prints your local secrets file
echo $STRIPE_SECRET_KEY  # a normal debugging step
docker inspect web       # config blobs often contain credentials
```

When an agent runs one of these — often while legitimately debugging something you asked it to fix — the secret value lands in the chat transcript. From there it's in the model's context, it may be in the provider's logs, and it may be in a screen recording or a shared session. You can't un-send it, so the safe response is to rotate the credential.

This isn't hypothetical. From the Claude Code issue tracker:

> *"Three confirmed incidents at one operator workstation in ~6 days. Each incident forced a credential rotation. None of these are exotic — they're shapes that came up during normal diagnosis work the model was asked to do."*
> — [anthropics/claude-code#65122](https://github.com/anthropics/claude-code/issues/65122)

The agents don't redact their own output, and the secret managers you already use (`op run`, `doppler run`, `infisical run`) inject secrets but don't redact either. ironrun adds the missing piece: it sits between the agent and the command so secrets flow **in** but never flow back **out**.

### The threat you probably haven't seen yet

When Claude Code runs a command that uses a secret — a `curl` with an Authorization header, a deploy script that reads DATABASE_URL — that command invocation is logged verbatim to:

```
~/.claude/projects/<hash>/YYYYMMDD_HHMMSS_*.jsonl
```

These JSONL files are Claude Code's conversation history. They contain every tool call, every shell command, every piece of output — including the secret values that appeared in those outputs. They persist between sessions and across project restarts.

One developer found this by accident:

> *"It will just grep the logs and try to find a working secret from other projects/past sessions"*

The logs are readable by any process with access to your home directory. If you've ever run a command through Claude Code that touched a secret, assume that value is in those logs.

ironrun redacts secret values from command output before it reaches the agent — so the values never enter the conversation, and never end up in the JSONL logs.

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  AI agent (Claude Code, Codex, Cursor, …)                   │
│                                                             │
│   "run the test suite"                                      │
│        │                                                    │
│        ▼                                                    │
│   run_sealed({argv})   ◄── one MCP tool call               │
│        │                                                    │
└────────┼────────────────────────────────────────────────────┘
         │  ironrun takes over here
         ▼
┌─────────────────────────────────────────────────────────────┐
│  ironrun                                                    │
│                                                             │
│  1. Check the human-approved project, dev environment, and  │
│     current agent session                                  │
│  2. Resolve its encrypted environment entries               │
│  3. Run the command with those secrets injected             │
│  4. Stream output through a redactor:                       │
│        any secret value that appears  →  [REDACTED]         │
│  5. Hand back exit code + cleaned output                    │
│                                                             │
│  Agent sees:   exit_code=0, stdout="ok  tests passed"      │
│  Agent doesn't see:   DATABASE_URL=postgres://…            │
└─────────────────────────────────────────────────────────────┘
```

By default, an agent can use arbitrary argv only during a temporary session you explicitly trust. Strict policy commands remain available for CI, production, and sensitive projects. Ironrun never has a tool that returns a secret’s value.

> ironrun adds approximately 5-10ms per command invocation: ~2ms for provider lookup (env/envfile) up to ~100ms for a 1Password CLI call. The redaction layer adds under 1ms for typical output sizes.

---

## Install

```bash
# curl (Linux/macOS — inspectable script, mandatory checksum verification)
curl -fsSL https://ironrun.dev/install.sh -o /tmp/ironrun-install.sh
bash /tmp/ironrun-install.sh

# Go (any platform)
go install github.com/generalized-labs/ironrun/cmd/ironrun@latest

# Verified npm launcher (Node 20+; available after the one-time npm bootstrap)
npx @generalized-labs/ironrun@latest
```

Windows (amd64) is a beta: download `ironrun_Windows_x86_64.zip` from the
[latest release](https://github.com/generalized-labs/ironrun/releases/latest)
and put `ironrun.exe` on your `PATH`.

Check it's on your path:

```bash
ironrun version
# ironrun 0.4.0
# A build from source prints a Go pseudo-version such as
# ironrun v0.0.0-20260817002148-219af21cab7f
```

### Requirements

Ironrun wraps the project vault's root key with your operating system's
credential manager, so it needs one to be present and unlocked:

| Platform | Requires | Notes |
| --- | --- | --- |
| macOS | `security` (built in) | The first vault write asks for Keychain authorization. |
| Linux | `secret-tool` (libsecret) | `apt install libsecret-tools` / `dnf install libsecret`. Without it Ironrun exits with `install libsecret secret-tool`. |
| Windows (beta) | Credential Manager (built in) | — |
| Headless / container / CI | nothing extra | See [Headless environments](#headless-environments) below. |

### Headless environments

By default the vault needs an interactive desktop session, because the OS
credential manager prompts before releasing the root key. In a container, a
plain SSH session, or on a Linux host without libsecret, opt in to an
owner-only key file instead:

```bash
export IRONRUN_VAULT_PROTECTOR=file
```

The root key is then written to `~/.ironrun/keys/<id>.key` with `0600`
permissions, and Ironrun refuses to read it if those permissions are ever
widened. Values stay encrypted in the vault exactly as before.

This is **weaker than the OS credential manager**: any process running as your
user can read the key file, with no prompt. It does not change what an agent can
reach — no MCP tool returns a value or the key — but it does remove the
operating system as a second gate. Ironrun never selects it for you; a headless
session gets an error explaining the choice rather than a silent downgrade.

For CI, you often don't need the vault at all. A version-1 policy with
`provider: env` reads values from the runner's own secret store and still
redacts them from command output, which is what keeps them out of build logs:

```yaml
version: "1"
provider: env
commands:
  - id: test
    argv: [npm, test]
    env:
      DATABASE_URL: "CI_DATABASE_URL"   # from GitHub Actions secrets
```

---

## Quickstart

Set up a project once:

```bash
cd your-project
ironrun setup
```

Setup previews every file it will write, detects `.env` key names without
displaying values, creates an encrypted `dev` environment, registers MCP
clients, and optionally installs the value-blind per-user service.

Then use bare `ironrun` from anywhere. It opens the global Projects and Inbox
workspace. Agent requests appear automatically; Enter opens the exact review
and resumes the waiting MCP call after approval or masked secret entry.

The everyday CLI is also intentionally short:

```bash
ironrun add OPENAI_API_KEY   # masked prompt; saves to the active environment
ironrun import .env          # preview names, confirm, encrypt, verify
ironrun new staging         # create and switch to a persistent environment
ironrun session             # create and switch to a 24-hour environment
ironrun use dev             # switch environments
ironrun envs                # list names and keys, never values
ironrun run test            # run the approved command named "test"
ironrun trust list          # inspect active trusted agent sessions
ironrun trust revoke ID     # stop one immediately
ironrun status              # value-blind project summary
```

Run `ironrun setup` when you also want project agent instructions and MCP
configuration. It looks at your project and writes three files:

- **`ironrun.yml`** — a starter policy. It detects your stack (npm/pnpm/yarn/bun, Go, Rust, Python) and your `.env`, and pre-fills commands like `test`, `dev`, and `build` with the env vars it found.
- **`.mcp.json`** — wires Claude Code up to ironrun (project-scoped MCP server, merged into any existing file).
- **`CLAUDE.md`, `AGENTS.md`, `.cursorrules`** — tell the agent (Claude Code, Codex, Cursor) to run commands via `run_sealed` instead of typing them into a shell.

New policies bind approved commands directly to encrypted environment entry
names. Storing or rotating a value never requires a policy edit:

```yaml
version: "2"
environment_set: active
require_agent_leases: true
allow_proposals: true

commands:
  - id: dev
    argv: [npm, run, dev]
    ttl: 0
    secrets: [DATABASE_URL, STRIPE_SECRET_KEY]

  - id: test
    argv: [npm, test]
    ttl: 120s
    secrets: [DATABASE_URL, STRIPE_SECRET_KEY]

  - id: build
    argv: [npm, run, build]
    ttl: 120s
```

Import or add values locally, then check the workspace:

```bash
chmod 600 .env
ironrun import .env
ironrun status
```

The import shows key names only, asks for confirmation, verifies the encrypted
copy, and warns that the plaintext source remains. Ironrun never offers reveal,
clipboard copy, or plaintext export.

Run one yourself to see the redaction:

```bash
ironrun run test
# npm test runs with DATABASE_URL and STRIPE_SECRET_KEY set.
# If a test logs the connection string, you'll see [REDACTED] instead.
```

### Existing version-1 policies

Version-1 provider aliases remain supported. Preview a reversible migration:

```bash
ironrun migrate
ironrun migrate --apply
```

Migration copies values transactionally, verifies encrypted storage, preserves
policy comments through an AST edit, keeps an ignored backup, and does not
delete legacy values. `ironrun migrate rollback ID` remains available until an
explicit `ironrun migrate cleanup ID --yes`.

### Project environment sets

For projects with more than one environment, manage the values entirely from
the terminal. On a new project, simply run `ironrun`: it creates a valid
local-vault policy, registers the project identity, creates `dev`, and opens the
control room. The original nested CLI remains available for scripts and
advanced operations:

```bash
ironrun env init dev
ironrun env set dev HYDRA_DB_API_KEY
ironrun env create staging
ironrun env clone dev staging
ironrun env use staging
ironrun env status
ironrun run hydra-bootstrap
```

Temporary session sets expire automatically (24 hours by default):

```bash
ironrun env create session --temporary --ttl 8h
ironrun env use session
ironrun env prune
```

Use `ironrun run --set staging <command-id>` for a one-run override. `env list`,
`env rotate`, `env delete`, `env remove`, `env doctor`, and `env import` cover
the remaining lifecycle. Imports accept owner-only dotenv files, display key
names but never values, and refuse project-local or group/other-readable files.
`env export` writes only a `KEY=` template; it never exports plaintext values.

Project metadata lives under `.ironrun/` and contains no secret values. The
encrypted vault lives outside the repository under `~/.ironrun/vaults/`. Every
environment has a rotating data key wrapped by a project root key in the native
OS credential manager. Existing per-value credential-manager records migrate
into the vault on first successful read, with vault commit before legacy delete.

### Terminal control room

Run Ironrun with no arguments in a terminal, or use the explicit command:

```bash
ironrun
ironrun tui
```

The TUI opens on the encrypted workspace: environments, masked environment/file
secret names, approved commands, and the actions people need most. Use arrows,
Enter, Escape, and Tab; press `/` for the action palette and `?` for help. A
detected `.env` can be reviewed by key name, partially selected, confirmed, and
verified after encrypted import. Ironrun never deletes the plaintext source for
you and warns while it remains. Requests, leases, and audit state live on
secondary tabs. There is no reveal, clipboard-copy, or plaintext-export action.

### Encrypted file secrets

File-backed secrets are stored as opaque encrypted bytes and materialized only
while an approved command runs. Declare a safe basename and the environment
variable that receives its temporary path:

```yaml
secrets:
  service-account:
    env: GOOGLE_APPLICATION_CREDENTIALS
    kind: file
    filename: service-account.json
    allow: [integration-test]
commands:
  - id: integration-test
    argv: [go, test, ./integration/...]
    secrets: [service-account]
```

Choose **Add secret file** in the TUI. Ironrun rejects symlinks, traversal,
unsafe basenames, permissive source files, and duplicate targets. At execution
it creates a unique owner-only directory outside the repository, writes the
file with owner-only permissions, injects only its path, redacts literal and
common encoded forms of the contents, and removes the directory after success,
failure, timeout, or cancellation. Validated stale crash remnants are removed
on startup.

Temporary plaintext necessarily exists on disk while the child process uses a
file secret. Cleanup limits its lifetime but cannot guarantee physical erasure
from SSD media. Use short command timeouts and revoke agent leases when access
is no longer needed.

### Revocable agent leases

Agent leases are opt-in for compatibility. Require them for MCP execution:

```yaml
version: "1"
provider: passthrough
require_agent_leases: true
```

An agent calls `request_lease` with policy command IDs, a reason, and a desired
TTL. The command remains blocked until a human approves it:

```bash
ironrun access list
ironrun access approve req_abc123...
ironrun access leases
ironrun access revoke lease_abc123...
```

Leases are bound to the exact MCP server session, environment, command set, and
expiry. Restarting the MCP server creates a new session; old leases do not
transfer. Revocation is checked before the next run.

### Trusted workspace sessions (the fast agent path)

For normal local development, an agent can call `request_workspace_access` or
attempt `run_sealed` with an `argv` array. Ironrun shows one request in the
global Inbox. Approve it once and the same MCP session can run normal commands
for the selected project and environment for two hours:

```bash
ironrun trust list
ironrun trust grant req_abc123
ironrun trust pause trust_abc123
ironrun trust extend trust_abc123 --ttl 2h
ironrun trust revoke trust_abc123
```

Trusted sessions are pinned to the MCP session, project, and environment. A
server restart creates a new session; an old grant cannot transfer. The default
scope is the current `dev` environment. `staging` and `prod` require a separate
explicit grant. Normal development network access is enabled, which means a
trusted agent could deliberately exfiltrate a secret through network or file
actions. Ironrun protects agent context, logs, and routine output; it is not an
OS sandbox for a process you choose to trust.

### Secret requests and encrypted chat capsules

The `request_secret` MCP tool accepts only a declared alias and reason. It has no
plaintext value field. Fulfill it directly through the TUI or masked CLI:

```bash
ironrun access fulfill req_abc123...
```

If the workflow specifically requires pasting through chat, encrypt the value
*before* it enters the transcript:

```bash
ironrun capsule create req_abc123...
# masked prompt; prints ir1.<ciphertext>
```

Paste only the `ir1.` ciphertext. The agent passes it to `claim_capsule`; Ironrun
decrypts and stores it locally. Capsules are project-bound, MCP-session-bound,
request-bound, expire within ten minutes, and become unusable after the request
is fulfilled. A plaintext key already pasted into chat cannot be retroactively
removed from model-provider logs and should be rotated.

### Local curl API

Start the owner-only Unix-socket API:

```bash
ironrun serve
curl --unix-socket .ironrun/ironrun.sock http://localhost/v1/status
curl --unix-socket .ironrun/ironrun.sock \
  -H 'Content-Type: application/json' \
  -d '{"command_id":"test","environment":"dev"}' \
  http://localhost/v1/run
```

The API exposes status, environment metadata, access requests, leases,
revocation, denial, and sealed execution. It refuses unknown JSON fields and
has no endpoint accepting plaintext secret values.

Now start your agent (`claude`, `cursor`, …). It sees `run_sealed` and asks for
one trusted workspace session before normal development work. It can then run
commands without ever holding the secret values.

### Using with Codex

Add ironrun to Codex's MCP server list:

```bash
codex mcp add ironrun -- ironrun mcp
```

Or add manually to `~/.codex/config.toml`:

```toml
[mcp_servers.ironrun]
enabled = true
command = "ironrun"
args = ["mcp"]
```

Then add to your project's `AGENTS.md` (the cross-agent instruction file that
Codex reads):

```
Use run_sealed for all commands that need credentials.
Do not run printenv, cat .env, or echo $VAR.
```

### Using with Cursor

Add ironrun to `~/.cursor/mcp.json` (merge, don't replace existing entries):

```json
{
  "mcpServers": {
    "ironrun": {
      "command": "ironrun",
      "args": ["mcp"]
    }
  }
}
```

Cursor loads this global MCP config for all projects. You'll also need a `CURSOR.md` or `.cursorrules` file in your project telling Cursor to use `run_sealed` instead of direct shell commands.

### Using any MCP-capable agent

Ironrun's agent boundary is a standard stdio MCP server, so any agent host that
supports local stdio MCP servers can use it. Add the equivalent of the
following configuration in that host, then put the generated `AGENTS.md`
instructions in the project:

```json
{
  "mcpServers": {
    "ironrun": {
      "command": "ironrun",
      "args": ["mcp"]
    }
  }
}
```

The agent first calls `request_workspace_access` for normal development (or
uses a strict `run_sealed` command with `command_id`). The human approves the
specific project and environment locally; the agent receives only status and
redacted output, never a secret value.

---

## Writing the policy by hand

The whole policy is one YAML file. Here's a realistic one for a service that deploys with a 1Password-stored token:

```yaml
version: "1"
provider: 1password

commands:
  - id: test
    argv: [npm, test]
    ttl: 120s
    env:
      DATABASE_URL: "op://Engineering/staging-db/url"

  - id: deploy
    argv: [./scripts/deploy.sh, production]
    ttl: 10m
    no_network: false                # deploy needs the network
    env:
      FLY_API_TOKEN: "op://Engineering/fly/token"
```

Every field:

```yaml
version: "1"                  # required — always "1" for now
provider: 1password           # where secrets come from (see table below)

commands:
  - id: deploy                # required — the name the agent calls
    argv: [./scripts/deploy.sh, production]
                              # required — exact command + args.
                              #   No shell, no pipes, no globs, no $VAR expansion.
    ttl: 10m                  # optional — kill the command after this long
    max_bytes: 10485760       # optional — cap stdout+stderr (here, 10 MB)
    no_network: true          # optional — block outbound network
                              #   (Linux: namespace, macOS: sandbox-exec)
    seccomp: true             # optional — Linux seccomp filter (default on;
                              #   set false to allow e.g. a debugger that needs ptrace)
    workdir: ./services/api   # optional — run from this directory
    env:                      # optional — secrets to inject, by reference
      DATABASE_URL: "op://Engineering/prod-db/url"
```

### Extra hardening (on by default)

- **Syscall filter** — on Linux the command runs under a seccomp denylist that blocks `ptrace`/`process_vm_readv` and similar memory-snooping syscalls. It fails open with a warning on unsupported kernels. Turn off per command with `seccomp: false`, policy-wide with `seccomp_default: false`, or globally with `IRONRUN_SECCOMP=off`.
- **Encoded-secret redaction** — base64, hex, and URL-encoded forms of a secret are redacted alongside the literal value, plus a warn-only entropy scan flags high-entropy tokens that slip through.
- **Audit log** — every run appends a tamper-evident, hash-chained record (command + argv + secret *names*, never values) to `$XDG_STATE_HOME/ironrun/audit.log`. Check it with `ironrun audit verify`; redirect or disable with `IRONRUN_AUDIT_LOG=<path|off>` or the top-level `audit_log:` field.

```bash
ironrun lint      # security review of the policy (shell argv, missing ttl, secrets + open egress, …)
ironrun audit verify   # confirm the audit log hasn't been tampered with
```

`argv` is a literal list, not a shell line. `["npm", "test"]` runs `npm test` directly — there's no shell in between, so an injected value can never be re-expanded or piped somewhere unexpected.

---

## Where secrets come from

Set `provider:` once, then reference each secret in `env:`.

| Provider | Reference format | Example |
|---|---|---|
| `envfile` | `envfile:<path>` (set on `provider:`) | `provider: "envfile:~/.secrets/myapp.env"` |
| `1password` | `op://vault/item/field` | `op://Engineering/stripe/secret_key` |
| `vault` | `vault://<path>#<field>` (KV v2; reads `VAULT_ADDR`/`VAULT_TOKEN`) | `vault://secret/myapp#DATABASE_URL` |
| `doppler` | `doppler://project/config/NAME` or just `NAME` | `doppler://myapp/prod/STRIPE_KEY` |
| `infisical` | `infisical://projectId/env/NAME` or just `NAME` | `infisical://abc123/prod/DB_URL` |
| `env` | `env:NAME` or just `NAME` | `env:DATABASE_URL` |
| `passthrough` | the literal value | `postgres://localhost/dev` |

### Recommended for local dev: the `envfile` provider

The `env` provider reads from your shell environment — which is exactly the thing agents can dump with `printenv`. The `envfile` provider avoids that: it keeps secrets in a file **outside your repo** and reads them only at the moment a command runs, so they're never in the agent's environment at all.

```bash
# 1. A secrets directory outside any git repo, locked to you
mkdir -p ~/.secrets && chmod 700 ~/.secrets

# 2. Your real secrets, one KEY=value per line
cat > ~/.secrets/myapp.env <<'EOF'
DATABASE_URL=postgres://app:s3cr3t@db.internal:5432/myapp
STRIPE_SECRET_KEY=sk_live_51Nabc123def456
RESEND_API_KEY=re_8Hk2Qa9xY
EOF
chmod 600 ~/.secrets/myapp.env

# 3. Point the policy at it
#    provider: "envfile:~/.secrets/myapp.env"
```

Now `ironrun run test` still has every secret, but the agent's shell has none of them — `printenv` and `cat .env` come up empty.

### envfile — secrets stored in a file, not shell environment

The safest setup for local development with AI agents. Secrets are read from a file that the agent's shell process never inherits.

```bash
# One-time setup
mkdir -p ~/.secrets && chmod 700 ~/.secrets
cat > ~/.secrets/myproject.env << 'EOF'
DATABASE_URL=postgres://user:***@localhost/mydb
API_KEY=sk_live_...
EOF
chmod 600 ~/.secrets/myproject.env
```

```yaml
# ironrun.yml
version: "1"
provider: "envfile:~/.secrets/myproject.env"

commands:
  - id: test
    argv: [go, test, ./...]
    ttl: 10m
    env:
      DATABASE_URL: DATABASE_URL   # reads from the file
      API_KEY: API_KEY
```

The agent running `printenv DATABASE_URL` sees nothing — the var isn't in the shell environment. ironrun reads it from the file at execution time.

---

## The MCP tools the agent gets

When ironrun runs as an MCP server (`ironrun mcp`), it exposes value-blind tools
that never return a secret value:

**`list_commands`** — what can I run? Returns command names and their argv, nothing else.

```
test:   [npm test]
build:  [npm run build]
deploy: [./scripts/deploy.sh production]
```

**`run_sealed`** — either run a strict saved command with `command_id: "<id>"`, or run exact argv after the human trusts the current workspace session with `argv: ["npm", "test"]`. It returns the exit code, duration, and redacted stdout/stderr.

**`request_workspace_access`** and **`workspace_status`** — request temporary
project/environment access and inspect safe session/environment metadata.

```
exit_code: 0
duration_ms: 4231

--- stdout ---
ok  myapp  4.2s

--- stderr ---
(empty)
```

**`validate_policy`** — is the policy well-formed? Returns the provider and command count.

---

## In CI / GitHub Actions

ironrun injects secrets for trusted runs and refuses untrusted ones, so a pull request from a fork can't trick your workflow into handing it production credentials. No configuration needed.

| Event | Secrets injected? |
|---|---|
| `push` to a branch in your repo | ✓ yes |
| `pull_request` from the same repo | ✓ yes |
| `pull_request` from a fork | ✗ no — blocked (`ErrCIUntrusted`) |
| `pull_request_target` | ✗ no — unless you set `IRONRUN_ALLOW_PRT=1` |

Use it as an action step:

```yaml
- name: Deploy (sealed)
  uses: generalized-labs/ironrun@v0
  with:
    command_id: deploy        # a command from your ironrun.yml
    policy: ironrun.yml       # optional, this is the default
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

Or just install the binary and run a command in any job:

```yaml
- run: go install github.com/generalized-labs/ironrun/cmd/ironrun@latest
- run: ironrun run test       # uses ironrun.yml from the repo
```

---

## What it does and doesn't protect

**It keeps secrets out of:**

- `printenv`, `env`, `echo $VAR`, and shell-expansion tricks the agent might run
- the agent's chat transcript and the model's context window
- a screen share, recording, or screenshot of that session
- CI logs that a fork-PR author could read

**It does not (in v0) protect against:**

- a command that deliberately writes a secret to a file and reads it back later
- network exfiltration by a command running with `no_network: false` (the default)
- secrets in files the command itself creates
- anyone who already has access to the machine ironrun runs on

ironrun guards the path between the agent and the command. It is not a sandbox for hostile code. See [SECURITY.md](SECURITY.md) for the full threat model and how to report an issue.

---

## How it compares to `op run` / `doppler run` / `infisical run`

Those tools resolve your secrets and inject them as environment variables — which is great, and ironrun does that too. The difference is everything that happens after the command starts printing:

| | ironrun | op / doppler / infisical run |
|---|---|---|
| Injects secrets as env vars | ✓ | ✓ |
| Redacts secret values from output | ✓ | ✗ |
| Exposes a `run_sealed` tool to agents | ✓ | ✗ |
| Strict saved-command mode for sensitive work | ✓ | ✗ |
| One trusted development session for normal agent work | ✓ | ✗ |
| Blocks fork-PR runs from getting secrets | ✓ | ✗ |
| Works across 1Password, Doppler, Infisical, env files | ✓ | each is tied to its own backend |

Doppler does ship an MCP server, but it [gives agents direct read access to secret values](https://docs.doppler.com/docs/mcp) — the opposite goal. ironrun's MCP server lets agents *run commands*, never *read secrets*.

---

## Troubleshooting

**Start with `ironrun doctor`.** It runs read-only checks in one shot: the policy parses, the provider CLI is installed and authenticated, the redactor strips a known secret, and every command's binary resolves on PATH. It exits non-zero and points at whatever is broken.

```bash
ironrun doctor
```
```
  ✓ ironrun.yml valid (v1, 3 command(s))
  ✓ provider 1password (ready)
  ✓ redaction self-test passed
  ✓ command "test": "go" resolves
  ✗ command "deploy": "./deploy.sh" not found on PATH
```

**`op: command not found`**
The 1Password CLI isn't installed or not in your PATH. Install it from [1password.com/downloads/command-line](https://1password.com/downloads/command-line/) and run `op signin`.

**`secret resolution failed`**
Run `ironrun doctor` — it validates the policy and checks that your provider is installed and authenticated (`op`, `vault`, `doppler`, `infisical`). (`ironrun validate` only parses the policy file; it does not check provider auth.)

**`command timed out`**
The command ran longer than its `ttl`. Increase it in `ironrun.yml`:
```yaml
- id: slow-test
  argv: [go, test, ./...]
  ttl: 30m   # was 10m
```

**`shell commands are not allowed`**
You can't use `sh`, `bash`, or other shells as `argv[0]`. If your command needs a shell, wrap it in a script file and call the script instead:
```yaml
- id: deploy
  argv: [./scripts/deploy.sh]   # not: [bash, -c, ./scripts/deploy.sh]
```

**`secret resolved to empty value — it cannot be redacted`**
Your provider returned an empty string for a secret. This usually means the secret reference is wrong (typo in the 1Password path, env var name doesn't match). Fix the reference in `ironrun.yml`.

**The agent ignores `run_sealed` and runs shell commands directly**
Check that `AGENTS.md`, `CLAUDE.md`, or `.cursorrules` exists in your project
root and contains clear instructions to use `run_sealed`. Agents respect these
files strongly for explicit directives.

---

## Contributing

PRs welcome. The bar is simple:

```bash
go build ./...
go test -race ./...   # keep it green
gofmt -w .            # keep it clean
```

Security threat model and disclosure process: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Built by [Generalized Labs](https://github.com/generalized-labs).
