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

Commands that require credentials MUST be run through ironrun.
Use the run_sealed MCP tool instead of running shell commands directly. Ask for
workspace access once, then use run_sealed with exact argv for normal work.

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
For normal development, call request_workspace_access (or run_sealed with argv)
and wait for the human to trust this project/environment session. Do not fall
back to a raw shell. Strict policy commands and propose_command remain available
for sensitive or production workflows.
`)
	return b.String()
}
