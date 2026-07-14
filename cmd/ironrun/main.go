// ironrun — sealed command execution for AI agents
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/buildinfo"
	"github.com/generalized-labs/ironrun/internal/execution"
	"github.com/generalized-labs/ironrun/internal/policy"
	ironmcp "github.com/generalized-labs/ironrun/mcp"
)

var policyPath string

func main() {
	// Note: when this binary is re-executed as the sealed-exec shim, the
	// sealedexec package's init() intercepts it (installing the seccomp filter
	// and execve'ing the target) before main runs — see internal/sealedexec.
	root := &cobra.Command{
		Use:   "ironrun",
		Short: "Sealed command execution for AI agents",
		Long: `ironrun runs trusted commands with secrets injected below agent visibility.
Secrets are resolved from your secret manager, injected into the child process
environment, and redacted from all stdout/stderr output before the agent sees it.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVarP(&policyPath, "policy", "p", "ironrun.yml", "Path to policy file")
	root.Args = cobra.NoArgs
	root.RunE = func(cmd *cobra.Command, args []string) error {
		info, err := os.Stdout.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return cmd.Help()
		}
		return runTUI(policyPath)
	}

	root.AddGroup(
		&cobra.Group{ID: "everyday", Title: "Everyday commands:"},
		&cobra.Group{ID: "agents", Title: "Agents and sharing:"},
		&cobra.Group{ID: "setup", Title: "Setup and safety:"},
		&cobra.Group{ID: "advanced", Title: "Advanced commands:"},
	)
	add := func(group string, commands ...*cobra.Command) {
		for _, command := range commands {
			command.GroupID = group
			root.AddCommand(command)
		}
	}
	add("everyday", tuiCmd(), quickAddCmd(), quickNewCmd(), quickSessionCmd(), quickUseCmd(), quickEnvsCmd(), runCmd(), envCmd())
	add("agents", accessCmd(), capsuleCmd(), mcpCmd(), serveCmd())
	add("setup", initCmd(), doctorCmd(), validateCmd(), lintCmd())
	add("advanced", auditCmd(), reviewCmd(), approveCmd(), rejectCmd(), secretsCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runCmd: ironrun run <command-id> [-- extra validation args]
func runCmd() *cobra.Command {
	var setName string
	c := &cobra.Command{
		Use:     "exec <command-id>",
		Aliases: []string{"run"},
		Short:   "Execute a sealed command by its policy ID",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}

			auditLog, auditErr := audit.Open(audit.ResolvePath(f.AuditLog))
			if auditErr != nil {
				fmt.Fprintf(os.Stderr, "[ironrun] warning: audit log disabled: %v\n", auditErr)
			}
			defer auditLog.Close()

			res, err := execution.Run(context.Background(), f, policyPath, policyProjectRoot(policyPath), args[0], execution.Options{
				Environment: setName, Stdout: os.Stdout, Stderr: os.Stderr,
				Audit: auditLog, SessionID: audit.NewSessionID(),
			})
			if err != nil {
				return fmt.Errorf("execution failed: %w", err)
			}

			if res.Truncated {
				fmt.Fprintln(os.Stderr, "[ironrun] output truncated at max_bytes limit")
			}

			os.Exit(res.ExitCode)
			return nil
		},
	}
	c.Flags().StringVar(&setName, "set", "", "environment set to use for this run (overrides the active set)")
	return c
}

func mustWorkingDir() string { cwd, _ := os.Getwd(); return cwd }

// mcpCmd: ironrun mcp — starts an MCP stdio server
func mcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP stdio server (for Claude Code, Cursor, etc.)",
		Long: `Starts an MCP server over stdio. AI agents can call the run_sealed tool
to execute policy-authorized commands without seeing raw secret values.

Add to your Claude Code or Cursor MCP config:
  {
    "ironrun": {
      "command": "ironrun",
      "args": ["mcp", "--policy", "ironrun.yml"]
    }
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			return ironmcp.Serve(f, policyPath)
		},
	}
}

// validateCmd: ironrun validate — check policy file without executing
func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate a policy file without executing anything",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}
			fmt.Printf("Policy valid: %d command(s) defined, provider=%s\n",
				len(f.Commands), f.Provider)
			for _, c := range f.Commands {
				shell := ""
				if policy.IsShellString(c.Argv) {
					shell = " [WARNING: shell command will be denied at runtime]"
				}
				fmt.Printf("  • %s: %v%s\n", c.ID, c.Argv, shell)
			}
			return nil
		},
	}
}

func versionCmd() *cobra.Command {
	var verbose bool
	c := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ironrun v%s\n", buildinfo.String())
			if verbose {
				fmt.Printf("  commit: %s\n", buildinfo.Commit)
				fmt.Printf("  built:  %s\n", buildinfo.Date)
			}
		},
	}
	c.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print commit and build date")
	return c
}
