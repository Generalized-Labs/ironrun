# Frequently asked questions

## What is ironrun?

Sealed command execution for AI agents. You declare which commands an agent
may run in `ironrun.yml`; ironrun injects the needed secrets into the child
process's environment — below the agent's visibility — and redacts secret
values from everything the child prints before the agent (or you) sees it.
The agent gets the *result* of the command, never the credential.

## Do AI agents ever see my secret values?

Not through ironrun's paths: injection puts values only in the child
process's environment, and the redactor strips managed values (plus encoded
variants) from stdout/stderr. The audit log is value-blind by design, and
there is deliberately no command that prints a value. See
[concepts.md](concepts.md#honest-limits) for the residual risks we don't
claim to cover.

## Where are secrets stored?

In an encrypted local vault, never in `ironrun.yml`. On macOS that's the
Keychain; on Linux the Secret Service (`secret-tool`); values are also
cached in an encrypted envfile backend. Project metadata (key *names*,
environments, the project registry) lives under `~/.ironrun`. Values are
entered via masked prompts or stdin — never as CLI flags, which would leak
into shell history and process lists.

## What is `ironrun.yml`? Is it safe to commit?

Yes — commit it. It contains command allowlists, secret *names*, and policy,
never values. That's the whole point: the checked-in file is pointers, not
secrets. A teammate clones the repo, runs `ironrun init`, stores their own
values with `ironrun env set KEY`, and has working credentials without a
secret ever touching git.

## What's the difference between `run`, environments, and the dashboard?

- `ironrun run <command-id>` executes one reviewed command from `ironrun.yml`
  with its secrets injected — the primary interface for humans, CI, and
  agents alike.
- Environments (`dev`, `staging`, …) are named sets of values. `ironrun new`,
  `ironrun use`, `ironrun env set KEY` manage them; `run --set NAME` picks one
  per invocation.
- Bare `ironrun` (or `ironrun dashboard`) opens the terminal control room:
  projects, environments with masked values, and the inbox where agent lease
  requests wait for your approval.

## What are leases and approvals?

By default, an agent can't run arbitrary commands — only the IDs in
`ironrun.yml`, and (with `require_agent_leases`) only after you approve a
time-boxed lease for its session. The agent calls `request_lease` via MCP;
you see it in the inbox (`ironrun agents list`) and approve or deny.
`ironrun trust` manages longer-lived trusted sessions you explicitly grant.
Everything is revocable: `ironrun agents revoke LEASE_ID`.

## Does it work offline? Does it phone home?

Yes, and no. The vault, policy engine, redactor, and audit log are all
local. ironrun collects no telemetry ([telemetry.md](telemetry.md)). The only
network use is the secrets you choose to fetch (e.g. a 1Password provider
call during setup) and whatever the child command itself does — and
secret-bearing commands run network-isolated by default on Linux.

## Which platforms are supported?

Linux and macOS (amd64 + arm64). Windows is explicitly unsupported for the
OSS launch — secret-input commands fail loudly rather than degrade silently.
See [windows.md](windows.md).

## How is this different from 1Password/Doppler/Vault?

Those are secret *stores* with CLIs; ironrun is a sealed *execution* layer.
It doesn't compete on storage — it can front providers — it competes on the
guarantee that the thing running your command (human or agent) never holds
the credential. The closest pattern is `op run --` / `doppler run --`, taken
further: policy allowlists, lease approvals, output redaction, and a
value-blind audit trail built for agent workflows.

## I pasted a secret into chat / committed it to git. Now what?

Rotate it — a value that reached a transcript or git history can't be
un-seen. Then: `ironrun agent-scrub` exact-match scrubs agent transcript
stores; `ironrun git install-hooks` adds pre-commit/pre-push exact-value
checks so it doesn't happen again. Prevention, not cure.

## How do I uninstall?

```bash
sh /tmp/install-ironrun.sh --uninstall            # removes the binary
sh /tmp/install-ironrun.sh --uninstall --purge    # also deletes ~/.ironrun
```

`--purge` asks for typed confirmation (`--yes` for scripts). Details and
manual cleanup: [uninstall.md](uninstall.md).

## Is it open source? What's the license?

Yes — MIT. The security model is documented in
[ARCHITECTURE.md](ARCHITECTURE.md), and releases are reproducible and
Sigstore-signed ([INSTALL.md](INSTALL.md#reproducible-builds)).
