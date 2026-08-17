package main

import (
	"fmt"
	"strings"
)

// renderAgentInstructions produces the guardrail nudge written to each agent's
// project instructions (CLAUDE.md / AGENTS.md / .cursorrules). It supports:
// - Claude Code
// - OpenAI Codex
// - Grok (xAI)
// - Hermes (Nous Research)
// - Pi Agent & Custom LLM Loops
// - HumanLayer & Conductor
func renderAgentInstructions(cmds []DetectedCmd) string {
	var b strings.Builder
	b.WriteString(`# Project Instructions for AI Coding Agents

## Universal Rules: Handling Secrets & Credentials

All commands that require credentials or environment variables MUST be run through ironrun.
Ironrun encrypts all project secrets locally in an AES-256-GCM vault and redacts secrets
from stdout/stderr so they never leak into model context windows or conversation logs.

### 1. Using MCP (Claude Code, Codex, Cursor, Hermes, Conductor)
- Use the **run_sealed** MCP tool instead of executing raw shell commands directly.
- Call **request_workspace_access** or **run_sealed({argv: [...]})** to request temporary developer execution.
- Available pre-approved commands in ironrun.yml:
`)
	if len(cmds) == 0 {
		b.WriteString("  - (none detected yet — add commands to ironrun.yml)\n")
	} else {
		for _, c := range cmds {
			fmt.Fprintf(&b, "  - run_sealed({command_id: %q}) — %s\n", c.ID, c.Comment)
		}
	}
	b.WriteString(`
### 2. Using CLI / Shell (Grok, Pi Agent, HumanLayer, Terminal Agents)
- If you execute terminal commands, ALWAYS prefix them with:
    ironrun run <command-id>
  or during a trusted session:
    ironrun exec <command-id>
- NEVER run "printenv", "cat .env", or "echo $SECRET_VAR" to read credentials.
- NEVER hardcode secrets, API keys, or database URLs into source files.

### 3. Missing Credentials & Approvals
- If you need a new secret or a new command, call **request_secret** or **propose_command**.
- The human operator can fulfill requests or review proposals with:
    ironrun inbox
    ironrun review <proposal-id>
    ironrun approve <proposal-id>
`)
	return b.String()
}
