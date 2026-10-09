// ironrun — sealed command execution for AI agents
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	// Turn SIGPIPE into an EPIPE error on writes to stdout/stderr instead of
	// letting it kill ironrun. Without this, `ironrun run … | head` dies mid-run
	// (no cleanup), orphaning the child and leaving file-secret plaintext behind.
	// The channel is intentionally never drained — notifying is what flips the
	// kernel-default behavior; see os/signal docs on SIGPIPE.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	_ = execution.CleanupStale()
	root := &cobra.Command{
		Use:   "ironrun",
		Short: "Sealed command execution for AI agents",
		Long: `ironrun runs trusted commands with secrets injected below agent visibility.
Secrets are resolved from your secret manager, injected into the child process
environment, and redacted from all stdout/stderr output before the agent sees it.`,
		SilenceUsage: true,
		// Errors print through reportError (errors.go) so every failure gets
		// a teaching hint; cobra must not print them first.
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVarP(&policyPath, "policy", "p", "ironrun.yml", "Path to policy file")
	root.Args = cobra.NoArgs
	root.RunE = func(cmd *cobra.Command, args []string) error {
		info, err := os.Stdout.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return cmd.Help()
		}
		return runGlobalWorkspace(false)
	}

	root.AddGroup(
		&cobra.Group{ID: "everyday", Title: "Everyday commands:"},
		&cobra.Group{ID: "agents", Title: "Agents and sharing:"},
		&cobra.Group{ID: "setup", Title: "Setup and safety:"},
		&cobra.Group{ID: "advanced", Title: "Advanced commands:"},
		&cobra.Group{ID: "leak-prevention", Title: "Leak prevention:"},
	)
	add := func(group string, commands ...*cobra.Command) {
		for _, command := range commands {
			command.GroupID = group
			root.AddCommand(command)
		}
	}
	add("everyday", openCmd(), inboxCmd(), statusCmd(), quickAddCmd(), importCmd(), quickFileCmd(), quickNewCmd(), quickSessionCmd(), quickUseCmd(), quickEnvsCmd(), runCmd(), tuiCmd(), envCmd())
	add("agents", trustCmd(), accessCmd(), capsuleCmd(), mcpCmd(), daemonCmd(), serveCmd())
	add("setup", initCmd(), migrateCmd(), doctorCmd(), validateCmd(), lintCmd())
	add("advanced", projectsCmd(), auditCmd(), reviewCmd(), approveCmd(), rejectCmd(), secretsCmd(), versionCmd())
	add("leak-prevention", agentScrubCmd(), gitCmd(), ghCmd(), shellCmd(), historyCmd())

	if err := root.Execute(); err != nil {
		reportError(root, err)
		os.Exit(1)
	}
}

// runCmd: ironrun run <command-id> [-- extra validation args]
func runCmd() *cobra.Command {
	var setName string
	var disableSeccomp, disableEntropyScan, allowPRT, noSeal, emitGitHubMasks bool
	c := &cobra.Command{
		Use:     "run <command-id>",
		Aliases: []string{"exec"},
		Short:   "Execute a sealed command by its policy ID",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := policy.Load(policyPath)
			if err != nil {
				return err
			}

			auditLog, err := audit.Open(audit.ResolvePath(f.AuditLog))
			if err != nil {
				return fmt.Errorf("refusing to run without a verifiable audit log: %w", err)
			}
			defer auditLog.Close()

			// Turn SIGINT/SIGTERM/SIGHUP into context cancellation so the runner
			// tears down the whole child process group and cleanup (file-secret
			// removal, audit) runs, instead of ironrun dying and orphaning the child.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
			defer stop()

			res, err := execution.Run(ctx, f, policyPath, policyProjectRoot(policyPath), args[0], execution.Options{
				Environment: setName, Stdout: os.Stdout, Stderr: os.Stderr,
				Audit: auditLog, SessionID: audit.NewSessionID(),
				DisableSeccomp: disableSeccomp, DisableEntropyScan: disableEntropyScan,
				AllowPullRequestTarget: allowPRT, NoSeal: noSeal,
				EmitGitHubMasks: emitGitHubMasks,
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
	c.Flags().BoolVar(&disableSeccomp, "disable-seccomp", false,
		"WEAKENS SECURITY: do not install the Linux seccomp syscall filter for this run. The filter blocks ptrace/memory-read syscalls in the child; disabling it is only for diagnosing filter breakage. Logged loudly.")
	c.Flags().BoolVar(&disableEntropyScan, "disable-entropy-scan", false,
		"WEAKENS SECURITY: skip the post-run high-entropy scan that flags possibly-unredacted secrets in output. Logged loudly.")
	c.Flags().BoolVar(&allowPRT, "allow-pull-request-target", false,
		"WEAKENS SECURITY: allow secret exposure on GitHub pull_request_target CI events. pull_request_target runs untrusted PR code with secrets; only pass this when you have reviewed the PR. Logged loudly.")
	c.Flags().BoolVar(&noSeal, "no-seal", false,
		"WEAKENS SECURITY: do not seal the secret-carrying child (skips RLIMIT_CORE=0, re-enabling core dumps that capture the child's secrets). "+
			"TRADEOFF, stated plainly: the seal blocks CORE DUMPS, not debuggers — PR_SET_DUMPABLE cannot survive execve, so a same-UID debugger can attach to the child either way; use host Yama ptrace_scope if you need that. "+
			"Use --no-seal only when you need post-mortem core debugging of the child. Logged loudly.")
	c.Flags().BoolVar(&emitGitHubMasks, "emit-github-masks", false,
		"Emit ::add-mask:: workflow commands for every managed secret value (GitHub Actions log masking). "+
			"Operator flag only: pass it when you know this run is inside GitHub Actions. "+
			"The GITHUB_ACTIONS environment variable is deliberately NOT consulted, because the environment is agent-reachable.")
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
