package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize ironrun in the current project",
		Long: `Creates ironrun.yml, .claude/mcp.json, and CLAUDE.md in the current directory.
This sets up sealed command execution so AI agents use ironrun for all commands
that need credentials.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}

			project := filepath.Base(cwd)
			fmt.Printf("Initializing ironrun in %s...\n\n", project)

			// 1. Write ironrun.yml if it doesn't exist
			ymlPath := filepath.Join(cwd, "ironrun.yml")
			if _, err := os.Stat(ymlPath); err == nil {
				fmt.Println("  • ironrun.yml already exists — skipping")
			} else {
				ymlContent := generatePolicy(cwd)
				if err := os.WriteFile(ymlPath, []byte(ymlContent), 0644); err != nil {
					return fmt.Errorf("failed to write ironrun.yml: %w", err)
				}
				fmt.Println("  • Created ironrun.yml")
			}

			// 2. Write .claude/mcp.json
			claudeDir := filepath.Join(cwd, ".claude")
			mcpPath := filepath.Join(claudeDir, "mcp.json")
			if _, err := os.Stat(mcpPath); err == nil {
				fmt.Println("  • .claude/mcp.json already exists — skipping")
			} else {
				if err := os.MkdirAll(claudeDir, 0755); err != nil {
					return err
				}
				mcpConfig := map[string]any{
					"mcpServers": map[string]any{
						"ironrun": map[string]any{
							"command": "ironrun",
							"args":    []string{"mcp"},
						},
					},
				}
				data, _ := json.MarshalIndent(mcpConfig, "", "  ")
				if err := os.WriteFile(mcpPath, append(data, '\n'), 0644); err != nil {
					return fmt.Errorf("failed to write .claude/mcp.json: %w", err)
				}
				fmt.Println("  • Created .claude/mcp.json")
			}

			// 3. Write CLAUDE.md (agent instructions)
			claudeMdPath := filepath.Join(cwd, "CLAUDE.md")
			if _, err := os.Stat(claudeMdPath); err == nil {
				fmt.Println("  • CLAUDE.md already exists — skipping")
			} else {
				claudeMd := `# Project Instructions

## Commands

All commands that require credentials MUST be run through ironrun.
Use the run_sealed MCP tool instead of running shell commands directly.

Available commands (defined in ironrun.yml):
- run_sealed("test") — run the test suite
- run_sealed("dev") — start the dev server
- run_sealed("build") — production build

Do NOT run printenv, cat .env, or echo $VAR to read credential values.
Do NOT hardcode credential values in any file.
If you need a command not in ironrun.yml, ask the user to add it.
`
				if err := os.WriteFile(claudeMdPath, []byte(claudeMd), 0644); err != nil {
					return fmt.Errorf("failed to write CLAUDE.md: %w", err)
				}
				fmt.Println("  • Created CLAUDE.md")
			}

			fmt.Println()
			fmt.Println("Done! Next steps:")
			fmt.Println()
			fmt.Println("  1. Edit ironrun.yml — add your commands and env var names")
			fmt.Println("  2. Export your credentials: export $(cat .env | grep -v '^#' | xargs)")
			fmt.Println("  3. Validate: ironrun validate")
			fmt.Println("  4. Test: ironrun run <command-id>")
			fmt.Println()
			fmt.Println("Then start your AI agent — it will use run_sealed() via MCP automatically.")
			return nil
		},
	}
}

// generatePolicy detects the project type and generates a starter policy
func generatePolicy(dir string) string {
	var lines []string
	lines = append(lines, `version: "1"`)
	lines = append(lines, `provider: env`)
	lines = append(lines, "")
	lines = append(lines, "commands:")

	// Detect package manager and common scripts
	runner := "npm"
	if _, err := os.Stat(filepath.Join(dir, "bun.lockb")); err == nil {
		runner = "bun"
	} else if _, err := os.Stat(filepath.Join(dir, "bun.lock")); err == nil {
		runner = "bun"
	} else if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err == nil {
		runner = "pnpm"
	} else if _, err := os.Stat(filepath.Join(dir, "yarn.lock")); err == nil {
		runner = "yarn"
	}

	// Check for common env files to suggest env vars
	envVars := detectEnvVars(dir)
	envBlock := ""
	if len(envVars) > 0 {
		envBlock = "\n    env:"
		for _, v := range envVars {
			envBlock += fmt.Sprintf("\n      %s: env:%s", v, v)
		}
	}

	// Generate commands based on what we find
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		// Node/JS project
		lines = append(lines, fmt.Sprintf(`  - id: dev
    argv: [%s, run, dev]
    ttl: 0%s`, runner, envBlock))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf(`  - id: test
    argv: [%s, test]
    ttl: 120s%s`, runner, envBlock))
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf(`  - id: build
    argv: [%s, run, build]
    ttl: 120s`, runner))
	} else if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		// Go project
		lines = append(lines, fmt.Sprintf(`  - id: test
    argv: [go, test, ./...]
    ttl: 120s%s`, envBlock))
		lines = append(lines, "")
		lines = append(lines, `  - id: build
    argv: [go, build, ./...]
    ttl: 60s`)
	} else if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		// Rust project
		lines = append(lines, fmt.Sprintf(`  - id: test
    argv: [cargo, test]
    ttl: 120s%s`, envBlock))
		lines = append(lines, "")
		lines = append(lines, `  - id: build
    argv: [cargo, build]
    ttl: 120s`)
	} else if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		// Python project
		lines = append(lines, fmt.Sprintf(`  - id: test
    argv: [python, -m, pytest]
    ttl: 120s%s`, envBlock))
	} else {
		// Generic fallback
		lines = append(lines, `  # Add your commands here:
  # - id: test
  #   argv: [npm, test]
  #   ttl: 120s
  #   env:
  #     DATABASE_URL: env:DATABASE_URL`)
	}

	lines = append(lines, "")
	return strings.Join(lines, "\n")
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
