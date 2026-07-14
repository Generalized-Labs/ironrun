package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize ironrun in the current project",
		Long: `Creates ironrun.yml, .mcp.json, and agent instructions
(CLAUDE.md, AGENTS.md, .cursorrules) in the current directory.
Also registers ironrun with Codex (~/.codex/config.toml) and Cursor (~/.cursor/mcp.json).
This sets up sealed command execution so AI agents use ironrun for all commands
that need credentials.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			project := filepath.Base(cwd)
			fmt.Printf("Initializing ironrun in %s...\n\n", project)

			// Detect the project's real commands once; both the policy and the
			// agent instructions are generated from them so they stay in sync.
			envVars := detectEnvVars(cwd)
			cmds := detectCommands(cwd, envVars)

			// 1. Write ironrun.yml if it doesn't exist
			ymlPath := filepath.Join(cwd, "ironrun.yml")
			createdPolicy := false
			if _, err := os.Stat(ymlPath); err == nil {
				fmt.Println("  • ironrun.yml already exists — skipping")
			} else {
				ymlContent := generatePolicy(cmds, envVars)
				if err := os.WriteFile(ymlPath, []byte(ymlContent), 0644); err != nil {
					return fmt.Errorf("failed to write ironrun.yml: %w", err)
				}
				createdPolicy = true
				fmt.Println("  • Created ironrun.yml")
			}
			stdout, _ := os.Stdout.Stat()
			if createdPolicy && stdout != nil && stdout.Mode()&os.ModeCharDevice != 0 {
				if err := initializeLocalEnvironment(cwd); err != nil {
					return err
				}
				fmt.Println("  • Created encrypted environment dev")
			}

			// 2. Write/merge .mcp.json at the repo root. Claude Code reads
			//    project-scoped MCP servers from .mcp.json at the project root —
			//    NOT from .claude/mcp.json — so this is the file that actually
			//    registers run_sealed with Claude Code.
			if err := registerClaudeMCP(cwd); err != nil {
				fmt.Printf("  ⚠  Could not update .mcp.json: %v\n", err)
			}

			// 3. Write agent-instruction files so the "use run_sealed" guardrail
			//    fires across agents: CLAUDE.md (Claude Code), AGENTS.md (Codex,
			//    and the emerging cross-agent convention), .cursorrules (Cursor).
			instructions := renderAgentInstructions(cmds)
			for _, name := range []string{"CLAUDE.md", "AGENTS.md", ".cursorrules"} {
				writeAgentInstructions(cwd, name, instructions)
			}

			// 4. Register ironrun with Codex (~/.codex/config.toml)
			registerCodex()

			// 5. Register ironrun with Cursor (~/.cursor/mcp.json)
			if err := registerCursor(); err != nil {
				fmt.Printf("  ⚠  Could not update ~/.cursor/mcp.json: %v\n", err)
			}

			fmt.Println()
			fmt.Println("Done! Next steps:")
			fmt.Println()
			fmt.Println("  1. Run ironrun to open the local vault control room")
			fmt.Println("  2. Press s to add a secret, n for a project environment, or t for a 24h session")
			fmt.Println("  3. Check your setup: ironrun doctor")
			fmt.Println("  4. Test: ironrun run <command-id>")
			fmt.Println()
			fmt.Println("Then start your AI agent — it will use run_sealed() via MCP automatically.")
			fmt.Println("  • Claude Code: uses .mcp.json (per-project, already set up)")
			fmt.Println("  • Codex:       uses ~/.codex/config.toml (global, registered above)")
			fmt.Println("  • Cursor:      uses ~/.cursor/mcp.json (global, merged above)")
			return nil
		},
	}
}

// writeAgentInstructions writes the rendered instructions to cwd/name unless the
// file already exists, printing a status line either way.
func writeAgentInstructions(cwd, name, instructions string) {
	path := filepath.Join(cwd, name)
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  • %s already exists — skipping\n", name)
		return
	}
	if err := os.WriteFile(path, []byte(instructions), 0644); err != nil {
		fmt.Printf("  ⚠  Could not write %s: %v\n", name, err)
		return
	}
	fmt.Printf("  • Created %s\n", name)
}

// registerClaudeMCP merges ironrun into ./.mcp.json — the project-root file
// Claude Code reads for project-scoped MCP servers — preserving any existing
// entries. (.claude/mcp.json is NOT read by Claude Code.)
func registerClaudeMCP(cwd string) error {
	mcpPath := filepath.Join(cwd, ".mcp.json")

	config := map[string]any{"mcpServers": map[string]any{}}
	if existing, err := os.ReadFile(mcpPath); err == nil {
		if err := json.Unmarshal(existing, &config); err != nil {
			return fmt.Errorf("could not parse .mcp.json: %w", err)
		}
	}

	servers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		servers = map[string]any{}
		config["mcpServers"] = servers
	}

	if _, exists := servers["ironrun"]; exists {
		fmt.Println("  • Claude Code: ironrun already in .mcp.json — skipping")
		return nil
	}

	servers["ironrun"] = map[string]any{
		"command": "ironrun",
		"args":    []string{"mcp"},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(mcpPath, append(data, '\n'), 0644); err != nil {
		return err
	}
	fmt.Println("  • Wrote .mcp.json (Claude Code project MCP)")
	return nil
}

// registerCodex adds ironrun to the Codex MCP config if the codex binary is available.
// It checks whether ironrun is already registered before adding it.
func registerCodex() {
	codexBin, err := exec.LookPath("codex")
	if err != nil {
		fmt.Println("  • Codex: not found in PATH — to add ironrun manually, run:")
		fmt.Println("      codex mcp add ironrun -- ironrun mcp")
		return
	}

	// Check if ironrun is already registered
	listOut, err := exec.Command(codexBin, "mcp", "list").Output()
	if err == nil && bytes.Contains(listOut, []byte("ironrun")) {
		fmt.Println("  • Codex: ironrun already registered — skipping")
		return
	}

	// Register ironrun — codex mcp add uses `-- <command> [args...]` syntax for stdio servers
	addCmd := exec.Command(codexBin, "mcp", "add", "ironrun", "--", "ironrun", "mcp")
	if out, err := addCmd.CombinedOutput(); err != nil {
		fmt.Println("  ⚠  Codex: failed to register ironrun")
		fmt.Printf("     Error: %v\n%s\n", err, out)
		fmt.Println("     To add manually: codex mcp add ironrun -- ironrun mcp")
	} else {
		fmt.Println("  • Registered ironrun with Codex (~/.codex/config.toml)")
	}
}

// registerCursor merges ironrun into ~/.cursor/mcp.json, preserving existing entries.
func registerCursor() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not determine home directory: %w", err)
	}

	cursorDir := filepath.Join(home, ".cursor")
	cursorMCP := filepath.Join(cursorDir, "mcp.json")

	// Read existing config or start fresh
	config := map[string]any{
		"mcpServers": map[string]any{},
	}

	existing, err := os.ReadFile(cursorMCP)
	if err == nil {
		if err := json.Unmarshal(existing, &config); err != nil {
			return fmt.Errorf("could not parse ~/.cursor/mcp.json: %w", err)
		}
	}

	// Get or create the mcpServers map
	servers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		servers = map[string]any{}
		config["mcpServers"] = servers
	}

	// Check if ironrun is already present
	if _, exists := servers["ironrun"]; exists {
		fmt.Println("  • Cursor: ironrun already in ~/.cursor/mcp.json — skipping")
		return nil
	}

	// Add ironrun entry
	servers["ironrun"] = map[string]any{
		"command": "ironrun",
		"args":    []string{"mcp"},
	}

	// Write back
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		return fmt.Errorf("could not create ~/.cursor directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal cursor config: %w", err)
	}

	if err := os.WriteFile(cursorMCP, append(data, '\n'), 0644); err != nil {
		return fmt.Errorf("could not write ~/.cursor/mcp.json: %w", err)
	}

	fmt.Println("  • Merged ironrun into ~/.cursor/mcp.json")
	return nil
}

// generatePolicy renders a local-vault-first policy from detected commands.
// Detected credential names become aliases, but their values never enter the
// policy; users store them through the TUI or `ironrun env set`.
func generatePolicy(cmds []DetectedCmd, envVars []string) string {
	if len(cmds) == 0 {
		cmds = []DetectedCmd{{ID: "ironrun-health", Argv: []string{"ironrun", "version"}, TTL: "10s", Comment: "verify the local Ironrun installation"}}
	}
	allowed := make([]string, 0, len(cmds))
	for _, command := range cmds {
		if command.NeedsEnv {
			allowed = append(allowed, command.ID)
		}
	}
	var b strings.Builder
	b.WriteString("version: \"1\"\n")
	b.WriteString("provider: passthrough\n")
	b.WriteString("environment_set: active\n")
	b.WriteString("require_agent_leases: true\n")
	b.WriteString("# Let agents propose new commands for your approval (ironrun review / approve).\n")
	b.WriteString("allow_proposals: true\n")
	if len(envVars) > 0 && len(allowed) > 0 {
		b.WriteString("\nsecrets:\n")
		for _, key := range envVars {
			fmt.Fprintf(&b, "  %s:\n    env: %s\n    store: auto\n    allow: [%s]\n", key, key, strings.Join(allowed, ", "))
		}
	}
	b.WriteString("\ncommands:\n")

	for i, c := range cmds {
		b.WriteString(renderCommandBlock(c.ID, c.Argv, c.TTL, nil, c.Comment))
		if c.NeedsEnv && len(envVars) > 0 {
			fmt.Fprintf(&b, "    secrets: [%s]\n", strings.Join(envVars, ", "))
		}
		if i < len(cmds)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// detectEnvVars reads .env or .env.local and returns variable names (not values)
func detectEnvVars(dir string) []string {
	var vars []string
	seen := map[string]bool{}

	for _, name := range []string{".env", ".env.local", ".env.development"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				// Only include things that look like credentials
				lower := strings.ToLower(key)
				isSecret := strings.Contains(lower, "key") ||
					strings.Contains(lower, "secret") ||
					strings.Contains(lower, "token") ||
					strings.Contains(lower, "password") ||
					strings.Contains(lower, "url") ||
					strings.Contains(lower, "dsn") ||
					strings.Contains(lower, "connection")
				if isSecret && !seen[key] {
					vars = append(vars, key)
					seen[key] = true
				}
			}
		}
	}
	return vars
}
