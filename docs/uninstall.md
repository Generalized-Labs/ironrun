# Uninstalling ironrun

Use the installer you originally downloaded (any release's `install.sh`
works — uninstall doesn't depend on the version):

```bash
# Remove the binary. Checks your --dir, /usr/local/bin, ~/.local/bin,
# and wherever your shell currently finds ironrun (uses sudo if needed).
sh /tmp/install-ironrun.sh --uninstall

# Also delete ~/.ironrun: the project registry, encrypted secret stores,
# and pending approvals. Asks for typed DELETE confirmation;
# add --yes for non-interactive use.
sh /tmp/install-ironrun.sh --uninstall --purge --yes
```

## What each step removes

| Command | Removes | Keeps |
|---|---|---|
| `--uninstall` | The `ironrun` binary from every candidate location | Everything else |
| `--uninstall --purge` | The binary **and** `~/.ironrun` | npm cache, project files (below) |

`--purge` prints a recovery warning first: **there is no undo.**
ironrun has no plaintext export by design — values never leave the vault —
so anything only in `~/.ironrun` is gone for good. Re-enter secrets from
their sources after reinstalling.

## What uninstall never touches

- **The npm launcher cache** (`~/.cache/ironrun` on Linux, `~/Library/Caches/ironrun` on macOS) — delete it manually if
  you also used `npx @generalized-labs/ironrun`.
- **Project files** — `ironrun.yml`, `.mcp.json`, `CLAUDE.md`, `AGENTS.md`,
  `.cursorrules` stay in your repos. They're yours; remove them with git or
  `rm` if you want them gone. (`ironrun.yml` holds only names and policy,
  never values, so leaving it behind leaks nothing.)
- **MCP client registrations** — `~/.codex/config.toml` entries,
  `~/.cursor/mcp.json` entries, and the per-user daemon unit
  (`ironrun daemon uninstall` removes the service itself) are separate
  cleanup if you want a fully clean slate.
- **Homebrew / Go installs** — if you installed via `brew` or `go install`,
  remove with the same tool (`brew uninstall ironrun`,
  `rm $(go env GOPATH)/bin/ironrun`); the `install.sh` uninstaller only
  knows about binaries it could have placed.

## Reinstalling

Reinstall any time with the pinned, verified flow from
[INSTALL.md](INSTALL.md). A fresh `--purge`'d machine starts empty: run
`ironrun init` in your project and re-store values with
`ironrun env set KEY` (masked prompt).
