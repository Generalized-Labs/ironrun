package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/daemon"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/execution"
)

func initCmd() *cobra.Command {
	var yes, installDaemon bool
	cmd := &cobra.Command{
		Use:     "setup",
		Aliases: []string{"init"},
		Short:   "Initialize ironrun in the current project",
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
			stdout, _ := os.Stdout.Stat()
			interactive := stdout != nil && stdout.Mode()&os.ModeCharDevice != 0
			if interactive && !yes {
				fmt.Println("Setup preview (secret values are never displayed, stored, or transmitted):")
				fmt.Println("  • ironrun.yml — reviewed commands and secret names")
				fmt.Println("  • .mcp.json — project MCP registration")
				fmt.Println("  • CLAUDE.md, AGENTS.md, .cursorrules — agent safety instructions")
				fmt.Println("  • ~/.codex/config.toml and ~/.cursor/mcp.json — merged when clients exist")
				ok, confirmErr := confirm("Continue with these setup changes? [y/N] ")
				if confirmErr != nil {
					return confirmErr
				}
				if !ok {
					return fmt.Errorf("setup cancelled")
				}
			}

			// 1. Write ironrun.yml if it doesn't exist
			ymlPath := filepath.Join(cwd, "ironrun.yml")
			createdPolicy := false
			if _, err := os.Stat(ymlPath); err == nil {
				fmt.Println("  • ironrun.yml already exists — skipping")
			} else {
				ymlContent := generatePolicy(cmds, envVars)
				if err := os.WriteFile(ymlPath, []byte(ymlContent), 0600); err != nil {
					return fmt.Errorf("failed to write ironrun.yml: %w", err)
				}
				createdPolicy = true
				fmt.Println("  • Created ironrun.yml")
			}
			if createdPolicy && interactive {
				if err := initializeLocalEnvironment(cwd); err != nil {
					return err
				}
				fmt.Println("  • Created encrypted environment dev")
			}
			if err := registerProject(cwd); err != nil {
				return fmt.Errorf("register global project: %w", err)
			}
			fmt.Println("  • Registered project in the global Ironrun workspace")

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
			if interactive && !installDaemon {
				path, _, previewErr := daemon.UnitPreview()
				if previewErr == nil {
					fmt.Printf("\nOptional background service: %s\n", path)
					fmt.Println("It watches value-blind project/request metadata and exposes no secret-value RPC fields.")
					installDaemon, _ = confirm("Install and start it now? [y/N] ")
				}
			}
			if installDaemon {
				path, installErr := daemon.Install()
				if installErr != nil {
					fmt.Printf("  ⚠  Background service was not installed: %v\n", installErr)
					fmt.Println("     Retry: ironrun daemon install")
				} else {
					fmt.Printf("  • Installed value-blind background service: %s\n", path)
				}
			}

			fmt.Println()
			fmt.Println("Done! Next steps:")
			fmt.Println()
			fmt.Println("  1. Run ironrun to open Projects and the agent inbox")
			fmt.Println("  2. Press Enter on this project, then choose Add secret or Import .env")
			fmt.Println("  3. Check your setup: ironrun doctor")
			fmt.Println("  4. Test: ironrun run <command-id>")
			fmt.Println()
			fmt.Println("Then start your AI agent — it will use run_sealed() via MCP automatically.")
			fmt.Println("  • Claude Code: uses .mcp.json (per-project, already set up)")
			fmt.Println("  • Codex:       uses ~/.codex/config.toml (global, registered above)")
			fmt.Println("  • Cursor:      uses ~/.cursor/mcp.json (global, merged above)")

			if interactive && !yes {
				fmt.Println()
				if demo, _ := confirm("Run the 60-second guided demo? It stores a throwaway demo secret and shows sealed redaction live. [y/N] "); demo {
					runGuidedDemo(cwd)
				} else {
					fmt.Println("Skipped. Take it later any time: store a secret with `ironrun env set DEMO_TOKEN`,")
					fmt.Println("then run `ironrun run <command-id>` and watch values come back [REDACTED].")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the setup file preview non-interactively")
	cmd.Flags().BoolVar(&installDaemon, "daemon", false, "install and start the value-blind user service")
	return cmd
}

// runGuidedDemo walks a new user through ironrun's core loop in about a
// minute: store one throwaway secret, then run a sealed command that prints
// it — showing the value redacted before it reaches the screen. The demo
// value is randomly generated, so even a failure leaks nothing real.
//
// It teaches as it goes: masked input (never flags), encrypted-at-rest
// storage, below-visibility injection into the child, and output redaction.
func runGuidedDemo(cwd string) {
	fmt.Println()
	fmt.Println("—— Guided demo: your first sealed secret ——")
	fmt.Println()
	fmt.Println("Step 1 of 3 — store a demo secret.")
	fmt.Println("  I'll generate a random throwaway token, so nothing real is at")
	fmt.Println("  stake. Storing a real secret looks the same, except you type the")
	fmt.Println("  value into a masked prompt:  ironrun env set API_KEY")
	fmt.Println("  (values are never passed as flags — flags leak into shell history")
	fmt.Println("  and process lists).")

	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		fmt.Printf("  Could not generate a demo token: %v\n", err)
		fmt.Println("  Skip the demo and store a real secret instead: ironrun env set API_KEY")
		return
	}
	demoValue := "demo-" + hex.EncodeToString(raw[:])

	manager, err := envset.Open(cwd)
	if err != nil {
		fmt.Printf("  Could not open the encrypted environment store: %v\n", err)
		fmt.Println("  Run `ironrun doctor` to diagnose, then take the demo again any time.")
		return
	}
	set, err := manager.Ensure("dev")
	if err != nil {
		fmt.Printf("  Could not prepare the dev environment: %v\n", err)
		return
	}
	if err := manager.Put(set.Name, "DEMO_TOKEN", demoValue); err != nil {
		fmt.Printf("  Could not store the demo secret: %v\n", err)
		fmt.Println("  The manual equivalent: ironrun env set DEMO_TOKEN")
		return
	}
	fmt.Println("  ✓ Stored DEMO_TOKEN in the dev environment — encrypted at rest,")
	fmt.Println("    and the value never touched your shell history on the way in.")
	fmt.Println()
	fmt.Println("Step 2 of 3 — run a sealed command that prints it on purpose.")
	fmt.Println("  The child process really receives DEMO_TOKEN in its environment.")
	fmt.Println("  ironrun redacts the value from the output before it reaches your")
	fmt.Println("  screen — or your agent's context. Watch for it:")
	fmt.Println()
	fmt.Println("  $ printenv DEMO_TOKEN   (sealed: injected below visibility, output redacted)")
	if _, err := execution.RunWorkspace(context.Background(), cwd, set.Name,
		[]string{"printenv", "DEMO_TOKEN"},
		execution.Options{Stdout: os.Stdout, Stderr: os.Stderr, SessionID: audit.NewSessionID(), AllowWorkspaceNetwork: true}); err != nil {
		fmt.Printf("  The sealed run failed: %v\n", err)
		fmt.Println("  Run `ironrun doctor` to diagnose. The everyday equivalent is")
		fmt.Println("  `ironrun run <command-id>` for any command in ironrun.yml.")
		return
	}
	fmt.Println()
	fmt.Println("Step 3 of 3 — that's the whole model:")
	fmt.Println("  • Secrets live encrypted at rest; ironrun.yml holds only names.")
	fmt.Println("  • Values resolve into the child process's environment only —")
	fmt.Println("    never your shell, never the agent's context, never disk.")
	fmt.Println("  • Everything the child prints is redacted before anyone sees it.")
	fmt.Println()
	fmt.Println("  Clean up the demo:   ironrun env delete dev DEMO_TOKEN")
	fmt.Println("  Store a real secret: ironrun env set API_KEY   (masked prompt)")
	fmt.Println("  Run a real command:  ironrun run <command-id>")
}

// writeAgentInstructions writes the rendered instructions to cwd/name unless the
// file already exists, printing a status line either way.
func writeAgentInstructions(cwd, name, instructions string) {
	path := filepath.Join(cwd, name)
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  • %s already exists — skipping\n", name)
		return
	}
	if err := os.WriteFile(path, []byte(instructions), 0600); err != nil {
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
	if err := os.WriteFile(mcpPath, append(data, '\n'), 0600); err != nil {
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
	if err := os.MkdirAll(cursorDir, 0700); err != nil {
		return fmt.Errorf("could not create ~/.cursor directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal cursor config: %w", err)
	}

	if err := os.WriteFile(cursorMCP, append(data, '\n'), 0600); err != nil {
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
	var b strings.Builder
	b.WriteString("version: \"2\"\n")
	b.WriteString("environment_set: active\n")
	b.WriteString("require_agent_leases: true\n")
	b.WriteString("# Let agents propose new commands for your approval (ironrun review / approve).\n")
	b.WriteString("allow_proposals: true\n")
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
