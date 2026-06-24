package main

import (
	"fmt"
	"strings"
)

// renderAgentInstructions produces the guardrail nudge written to each agent's
// project instructions (CLAUDE.md / AGENTS.md / .cursorrules). The available
// commands are generated from the ACTUAL policy ids so the agent sees what it
// can really run — not stale examples.
func renderAgentInstructions(cmds []DetectedCmd) string {
	var b strings.Builder
	b.WriteString(`# Project Instructions

## Commands

All commands that require credentials MUST be run through ironrun.
Use the run_sealed MCP tool instead of running shell commands directly.

Available commands (defined in ironrun.yml):
`)
	if len(cmds) == 0 {
		b.WriteString("- (none detected yet — add commands to ironrun.yml)\n")
	} else {
		for _, c := range cmds {
			fmt.Fprintf(&b, "- run_sealed(%q) — %s\n", c.ID, c.Comment)
		}
	}
	b.WriteString("\n" + `Do NOT run printenv, cat .env, or echo $VAR to read credential values.
Do NOT hardcode credential values in any file.
If you need a command that is not listed, call propose_command — it stages the
command for the user to approve with ` + "`ironrun approve <id>`" + ` and does NOT
run anything. Do not fall back to running it in a raw shell.
`)
	return b.String()
}
