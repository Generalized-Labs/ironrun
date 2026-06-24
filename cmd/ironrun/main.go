// ironrun — sealed command execution for AI agents
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/buildinfo"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
	ironmcp "github.com/generalized-labs/ironrun/mcp"
)

var policyPath string

func main() {
	root := &cobra.Command{
		Use:   "ironrun",
		Short: "Sealed command execution for AI agents",
		Long: `ironrun runs trusted commands with secrets injected below agent visibility.
Secrets are resolved from your secret manager, injected into the child process
environment, and redacted from all stdout/stderr output before the agent sees it.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVarP(&policyPath, "policy", "p", "ironrun.yml", "Path to policy file")

	root.AddCommand(runCmd())
	root.AddCommand(mcpCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(initCmd())
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// runCmd: ironrun run <command-id> [-- extra validation args]
func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run <command-id>",
		Short: "Execute a sealed command by its policy ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}

			pCmd, err := f.Lookup(args[0])
			if err != nil {
				return err
			}

			p, err := provider.New(f.Provider)
			if err != nil {
				return err
			}

			secrets, err := provider.ResolveAll(p, pCmd.Env)
			if err != nil {
				return fmt.Errorf("secret resolution failed: %w", err)
			}

			res, err := runner.Run(context.Background(), pCmd, runner.Options{
				Stdout:  os.Stdout,
				Stderr:  os.Stderr,
				Secrets: secrets,
			})
			if err != nil {
				return fmt.Errorf("execution failed: %w", err)
			}

			if res.Truncated {
				fmt.Fprintln(os.Stderr, "[ironrun] output truncated at max_bytes limit")
			}
			if res.RedactionCount > 0 {
				fmt.Fprintf(os.Stderr, "[ironrun] %d secret value(s) redacted from output\n", res.RedactionCount)
			}

			os.Exit(res.ExitCode)
			return nil
		},
	}
}

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
			return ironmcp.Serve(f)
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
