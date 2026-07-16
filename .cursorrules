# Project Instructions

## Commands

All commands that require credentials MUST be run through ironrun.
Use the run_sealed MCP tool instead of running shell commands directly.

Available commands (defined in ironrun.yml):
- run_sealed("test") — go test ./...
- run_sealed("build") — go build ./...

Do NOT run printenv, cat .env, or echo $VAR to read credential values.
Do NOT hardcode credential values in any file.
If you need a command that is not listed, call propose_command — it stages the
command for the user to approve with `ironrun approve <id>` and does NOT
run anything. Do not fall back to running it in a raw shell.
