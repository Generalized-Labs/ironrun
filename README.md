# ironrun

**Run commands through your AI agent without your secrets ending up in its context.**

[![CI](https://github.com/generalized-labs/ironrun/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/generalized-labs/ironrun/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/generalized-labs/ironrun)](https://goreportcard.com/report/github.com/generalized-labs/ironrun)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/generalized-labs/ironrun/blob/main/LICENSE)

---

ironrun is a small command runner. You list the commands an AI agent is allowed to run (your tests, your dev server, a deploy script) in one file. The agent runs them by name through ironrun instead of typing shell commands itself. ironrun injects your real secrets into the command, and strips any secret value back out of the output before the agent ever sees it.

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

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  AI agent (Claude Code, Codex, Cursor, …)                   │
│                                                             │
│   "run the test suite"                                      │
│        │                                                    │
│        ▼                                                    │
│   run_sealed("test")   ◄── one MCP tool call               │
│        │                                                    │
└────────┼────────────────────────────────────────────────────┘
         │  ironrun takes over here
         ▼
┌─────────────────────────────────────────────────────────────┐
│  ironrun                                                    │
│                                                             │
│  1. Look up "test" in ironrun.yml — is it allowed?          │
│  2. Resolve its secrets from your manager (1Password, …)    │
│  3. Run the command with those secrets injected             │
│  4. Stream output through a redactor:                       │
│        any secret value that appears  →  [REDACTED]         │
│  5. Hand back exit code + cleaned output                    │
│                                                             │
│  Agent sees:   exit_code=0, stdout="ok  tests passed"      │
│  Agent doesn't see:   DATABASE_URL=postgres://…            │
└─────────────────────────────────────────────────────────────┘
```

The agent can only run commands you've listed — it can't ask ironrun to run an arbitrary shell command, and there's no tool that returns a secret's value.

---

## Install

```bash
# curl (Linux/macOS — no Go toolchain needed, verifies the checksum)
curl -fsSL https://raw.githubusercontent.com/generalized-labs/ironrun/main/install.sh | bash

# Go (any platform)
go install github.com/generalized-labs/ironrun/cmd/ironrun@latest

# Homebrew (from the first tagged release onward)
brew install generalized-labs/tap/ironrun
```

Check it's on your path:

```bash
ironrun version
# ironrun 0.2.0   (a source build prints "ironrun dev")
```

---

## Quickstart

From the root of any project:

```bash
ironrun init
```

This looks at your project and writes three files:

- **`ironrun.yml`** — a starter policy. It detects your stack (npm/pnpm/yarn/bun, Go, Rust, Python) and your `.env`, and pre-fills commands like `test`, `dev`, and `build` with the env vars it found.
- **`.claude/mcp.json`** — wires Claude Code up to ironrun.
- **`CLAUDE.md`** — tells the agent to run commands via `run_sealed` instead of typing them into a shell.

For a Node project, the generated `ironrun.yml` looks like this:

```yaml
version: "1"
provider: env          # secrets come from the current environment, by name

commands:
  - id: dev
    argv: [npm, run, dev]
    ttl: 0               # no timeout — long-running dev server
    env:
      DATABASE_URL: env:DATABASE_URL
      STRIPE_SECRET_KEY: env:STRIPE_SECRET_KEY

  - id: test
    argv: [npm, test]
    ttl: 120s
    env:
      DATABASE_URL: env:DATABASE_URL
      STRIPE_SECRET_KEY: env:STRIPE_SECRET_KEY

  - id: build
    argv: [npm, run, build]
    ttl: 120s
```

Load your secrets, then check the policy:

```bash
set -a; source .env; set +a    # put .env values into the environment
ironrun validate
# Policy valid: 3 command(s) defined, provider=env
#   • dev:   [npm run dev]
#   • test:  [npm test]
#   • build: [npm run build]
```

Run one yourself to see the redaction:

```bash
ironrun run test
# npm test runs with DATABASE_URL and STRIPE_SECRET_KEY set.
# If a test logs the connection string, you'll see [REDACTED] instead.
```

Now start your agent (`claude`, `cursor`, …). It sees `run_sealed` as a tool and uses it to run `test`, `dev`, and `build` — without ever holding the secret values.

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
    workdir: ./services/api   # optional — run from this directory
    env:                      # optional — secrets to inject, by reference
      DATABASE_URL: "op://Engineering/prod-db/url"
```

`argv` is a literal list, not a shell line. `["npm", "test"]` runs `npm test` directly — there's no shell in between, so an injected value can never be re-expanded or piped somewhere unexpected.

---

## Where secrets come from

Set `provider:` once, then reference each secret in `env:`.

| Provider | Reference format | Example |
|---|---|---|
| `envfile` | `envfile:<path>` (set on `provider:`) | `provider: "envfile:~/.secrets/myapp.env"` |
| `1password` | `op://vault/item/field` | `op://Engineering/stripe/secret_key` |
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

---

## The MCP tools the agent gets

When ironrun runs as an MCP server (`ironrun mcp`), it exposes exactly three tools — none of which return a secret value:

**`list_commands`** — what can I run? Returns command names and their argv, nothing else.

```
test:   [npm test]
build:  [npm run build]
deploy: [./scripts/deploy.sh production]
```

**`run_sealed("<id>")`** — run one of them. Returns the exit code, duration, and redacted stdout/stderr.

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
| Allowlist — agent can't run arbitrary commands | ✓ | ✗ |
| Blocks fork-PR runs from getting secrets | ✓ | ✗ |
| Works across 1Password, Doppler, Infisical, env files | ✓ | each is tied to its own backend |

Doppler does ship an MCP server, but it [gives agents direct read access to secret values](https://docs.doppler.com/docs/mcp) — the opposite goal. ironrun's MCP server lets agents *run commands*, never *read secrets*.

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
