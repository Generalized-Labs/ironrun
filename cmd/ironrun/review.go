package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/pending"
	"github.com/generalized-labs/ironrun/internal/policy"
)

// reviewCmd: ironrun review — list agent-proposed commands awaiting approval.
func reviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "review",
		Short: "Review commands agents have proposed for your approval",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			path := pending.Path(policyPath)
			store, err := pending.Load(path)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			if len(store.Proposals) == 0 {
				fmt.Fprintln(out, "No pending proposals.")
				return nil
			}
			fmt.Fprintf(out, "%d command(s) awaiting your approval (%s)\n\n", len(store.Proposals), path)
			for _, p := range store.Proposals {
				printProposal(out, p)
			}
			fmt.Fprintln(out, "Approve:  ironrun approve <id>      Reject:  ironrun reject <id>")
			return nil
		},
	}
}

// printProposal renders one proposal so a human sees exactly what it would run
// and which secrets it would receive — the anti-rubber-stamp surface.
func printProposal(out io.Writer, p pending.Proposal) {
	fmt.Fprintf(out, "  %s\n", p.ID)
	fmt.Fprintf(out, "      argv:   %s\n", strings.Join(p.Argv, " "))
	if len(p.Env) > 0 {
		names := make([]string, 0, len(p.Env))
		for k := range p.Env {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(out, "      env:    %s  <-  %s\n", k, p.Env[k])
		}
	} else {
		fmt.Fprintln(out, "      env:    (none)")
	}
	if p.Reason != "" {
		fmt.Fprintf(out, "      reason: %s\n", p.Reason)
	}
	if flag := riskFlag(p); flag != "" {
		fmt.Fprintf(out, "      !  %s\n", flag)
	}
	fmt.Fprintln(out)
}

var networkBins = map[string]bool{
	"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true, "rsync": true,
	"nc": true, "ncat": true, "telnet": true, "psql": true, "mysql": true, "mongosh": true,
	"redis-cli": true, "http": true, "httpie": true, "aws": true, "gcloud": true, "kubectl": true,
}

func riskFlag(p pending.Proposal) string {
	var flags []string
	if len(p.Argv) > 0 && networkBins[filepath.Base(p.Argv[0])] {
		flags = append(flags, "reaches the network — review the target carefully")
	}
	if n := len(p.Env); n > 0 {
		flags = append(flags, fmt.Sprintf("receives %d secret(s)", n))
	}
	return strings.Join(flags, "; ")
}

// approveCmd: ironrun approve <id> — promote a proposal into ironrun.yml.
func approveCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "approve <id>",
		Short: "Approve a proposed command and add it to ironrun.yml",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			path := pending.Path(policyPath)
			store, err := pending.Load(path)
			if err != nil {
				return err
			}
			p := store.Find(id)
			if p == nil {
				return fmt.Errorf("no pending proposal with id %q (run `ironrun review`)", id)
			}
			// Re-validate at approve time (defense in depth).
			if policy.IsShellString(p.Argv) {
				return fmt.Errorf("refusing to approve %q: shell commands are not allowed", id)
			}
			f, err := policy.Load(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}
			if _, lerr := f.Lookup(id); lerr == nil {
				return fmt.Errorf("a command with id %q already exists in %s", id, policyPath)
			}

			out := c.OutOrStdout()
			printProposal(out, *p)
			if !yes {
				fmt.Fprintf(out, "Approve %q and add it to %s? [y/N] ", id, policyPath)
				line, _ := bufio.NewReader(c.InOrStdin()).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(line)) != "y" {
					fmt.Fprintln(out, "Aborted.")
					return nil
				}
			}

			if err := appendCommandToPolicy(policyPath, *p); err != nil {
				return err
			}
			store.Remove(id)
			if err := pending.Save(path, store); err != nil {
				return err
			}
			fmt.Fprintf(out, "Approved %q -> added to %s. The agent can now run it via run_sealed.\n", id, policyPath)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return cmd
}

// rejectCmd: ironrun reject <id> — discard a proposal (never touches ironrun.yml).
func rejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <id>",
		Short: "Reject a proposed command",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := args[0]
			path := pending.Path(policyPath)
			store, err := pending.Load(path)
			if err != nil {
				return err
			}
			if _, ok := store.Remove(id); !ok {
				return fmt.Errorf("no pending proposal with id %q", id)
			}
			if err := pending.Save(path, store); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "Rejected %q. %s unchanged.\n", id, policyPath)
			return nil
		},
	}
}

// appendCommandToPolicy appends an approved proposal as a YAML command block to
// the raw policy text (not via yaml.Marshal — policy.Duration has no MarshalYAML
// and re-emitting would mangle TTLs and strip comments), then re-parses to
// confirm the merge is valid, rolling back on failure.
func appendCommandToPolicy(policyPath string, p pending.Proposal) error {
	orig, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	comment := ""
	if p.Reason != "" {
		comment = "approved: " + p.Reason
	}
	block := renderCommandBlock(p.ID, p.Argv, "120s", p.Env, comment)

	text := string(orig)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += "\n" + block
	if err := os.WriteFile(policyPath, []byte(text), 0o644); err != nil {
		return err
	}
	if _, err := policy.Load(policyPath); err != nil {
		_ = os.WriteFile(policyPath, orig, 0o644) // roll back
		return fmt.Errorf("merged policy failed to parse (rolled back): %w", err)
	}
	return nil
}
