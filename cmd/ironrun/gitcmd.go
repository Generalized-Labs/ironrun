package main

import (
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/githooks"
)

// gitCmd: ironrun git — git leak-prevention helpers.
func gitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "git",
		Short: "Git leak prevention: install blocking hooks, scan diffs",
	}
	c.AddCommand(
		gitInstallHooksCmd(),
		gitUninstallHooksCmd(),
		gitCheckStagedCmd(),
		gitCheckPushCmd(),
		gitScanDiffCmd(),
	)
	return c
}

// gitInstallHooksCmd: ironrun git install-hooks — per-repo pre-commit (blocks)
// and pre-push hooks, plus .gitignore coverage for .ironrun/.
func gitInstallHooksCmd() *cobra.Command {
	var force bool
	var repo string
	c := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install pre-commit/pre-push hooks that block secret leaks",
		Long: `Installs blocking git hooks into the current repository:

  pre-commit — BLOCKS the commit when the staged diff contains a secret.
               Layer 1: gitleaks (or Betterleaks) on the staged diff, when
               present on PATH. Layer 2: ironrun's exact-value check of the
               staged diff against every managed vault value + encoded
               variants — catches novel token formats no regex covers.
  pre-push   — BLOCKS the push when the pushed commit range contains one.

Also appends .ironrun/ to .gitignore (repo-local state must never be
committed). Idempotent: re-running rewrites ironrun-managed hooks and never
duplicates .gitignore entries. A foreign (non-ironrun) hook is left alone
unless --force is given.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			root := repo
			if root == "" {
				root = mustWorkingDir()
			}
			root, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			if _, err := exec.Command("git", "-C", root, "rev-parse", "--git-dir").CombinedOutput(); err != nil {
				return fmt.Errorf("%s is not a git repository", root)
			}
			res, err := githooks.Install(root, force)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "ironrun git install-hooks")
			fmt.Fprintf(out, "  hooks dir: %s\n", res.HooksDir)
			if res.PreCommit != "" {
				fmt.Fprintf(out, "  wrote pre-commit: %s\n", res.PreCommit)
			}
			if res.PrePush != "" {
				fmt.Fprintf(out, "  wrote pre-push:   %s\n", res.PrePush)
			}
			if res.HooksRewrote == 0 {
				fmt.Fprintln(out, "  hooks already installed (byte-identical)")
			}
			for _, e := range res.GitignoreAdds {
				fmt.Fprintf(out, "  .gitignore: added %s\n", e)
			}
			if _, err := exec.LookPath("gitleaks"); err != nil {
				if _, err := exec.LookPath("betterleaks"); err != nil {
					fmt.Fprintln(out, "  note: neither gitleaks nor Betterleaks is on PATH — the scanner layer will warn-and-skip until you install one")
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "replace a pre-existing non-ironrun hook")
	c.Flags().StringVar(&repo, "repo", "", "repository root (default: current directory)")
	return c
}

// gitUninstallHooksCmd: ironrun git uninstall-hooks — removes ironrun-managed
// hooks and the managed .gitignore section. Foreign hooks are left alone.
func gitUninstallHooksCmd() *cobra.Command {
	var repo string
	c := &cobra.Command{
		Use:   "uninstall-hooks",
		Short: "Remove ironrun-managed git hooks",
		Long: `Removes the pre-commit and pre-push hooks installed by ` + "`ironrun git install-hooks`" + `,
plus the managed .gitignore section. Only hooks carrying the ironrun marker
are removed; a foreign (non-ironrun) hook is left alone. Idempotent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			root := repo
			if root == "" {
				root = mustWorkingDir()
			}
			root, err := filepath.Abs(root)
			if err != nil {
				return err
			}
			res, err := githooks.Uninstall(root)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, "ironrun git uninstall-hooks")
			if len(res.HooksRemoved) == 0 {
				fmt.Fprintln(out, "  no ironrun-managed hooks found")
			}
			for _, p := range res.HooksRemoved {
				fmt.Fprintf(out, "  removed hook: %s\n", p)
			}
			if res.GitignoreCleaned {
				fmt.Fprintln(out, "  .gitignore: removed managed section")
			}
			return nil
		},
	}
	c.Flags().StringVar(&repo, "repo", "", "repository root (default: current directory)")
	return c
}

// gitCheckStagedCmd: ironrun git check-staged — invoked by the pre-commit
// hook. Exits non-zero with a value-free message when the staged diff
// contains a managed secret.
func gitCheckStagedCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "check-staged",
		Short:  "Block when the staged diff contains a managed secret (hook helper)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			diff, err := exec.Command("git", "diff", "--cached", "--no-color").CombinedOutput()
			if err != nil {
				return fmt.Errorf("git diff --cached: %w", err)
			}
			return blockOnHits("staged diff", string(diff))
		},
	}
}

// gitCheckPushCmd: ironrun git check-push — invoked by the pre-push hook with
// the push plan on stdin ("<local ref> <local sha> <remote ref> <remote sha>"
// per line). Computes the commit range per ref and scans it.
func gitCheckPushCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "check-push",
		Short:  "Block when pushed commits contain a managed secret (hook helper)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}
			for _, line := range strings.Split(strings.TrimSpace(string(plan)), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 4 {
					continue
				}
				localRef, localSha, _, remoteSha := fields[0], fields[1], fields[2], fields[3]
				if isZeroSha(localSha) {
					continue // branch deletion: nothing to scan
				}
				// A zero remote sha means a new branch — the highest-risk
				// push; pushRange scans it via the new-branch heuristic.
				revArgs, err := pushRange(localRef, localSha, remoteSha)
				if err != nil {
					return err
				}
				args := append([]string{"log", "-p", "--no-color"}, revArgs...)
				diff, err := exec.Command("git", args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("git log for %s: %w", localRef, err)
				}
				if err := blockOnHits("push of "+localRef, string(diff)); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// gitScanDiffCmd: ironrun git scan-diff — reads a diff from stdin, exits 1
// with a value-free message on the first managed-secret hit.
func gitScanDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "scan-diff",
		Short:  "Exit non-zero when stdin diff contains a managed secret (hook helper)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			diff, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}
			return blockOnHits("diff", string(diff))
		},
	}
}

// pushRange returns the git-log revision arguments covering the commits a
// push would newly publish. For branch updates it is old..new; for a new
// branch it is the commits in new not reachable from any remote-tracking ref.
func pushRange(localRef, localSha, remoteSha string) ([]string, error) {
	// This command is only called with a non-zero remote sha; localSha zero
	// cannot happen for a push, but guard anyway.
	if isZeroSha(localSha) {
		return nil, fmt.Errorf("refusing to scan empty push for %s", localRef)
	}
	if !isZeroSha(remoteSha) {
		return []string{remoteSha + ".." + localSha}, nil
	}
	// New-branch heuristic: commits not yet on any remote.
	out, err := exec.Command("git", "rev-list", localSha, "--not", "--remotes").CombinedOutput()
	if err == nil && len(strings.Fields(string(out))) > 0 {
		return []string{localSha, "--not", "--remotes"}, nil
	}
	// Fallback: scan the branch tip against HEAD.
	return []string{"HEAD.." + localSha}, nil
}

// blockOnHits exits with a clear, value-free message when text contains any
// managed secret. The message names aliases and sha8 fingerprints only.
//
// It FAILS CLOSED when the vault cannot be loaded: these hooks promise to
// block secrets, and a hook that cannot check anything must not pass. (The
// pre-push hook has no other layer at all, so warn-and-pass there would be
// pure theater.) The error message says how to recover.
func blockOnHits(where, text string) error {
	secrets, err := loadActiveSecrets()
	if err != nil {
		return fmt.Errorf("ironrun: BLOCKED — exact-value check could not load the vault (%v). Run `ironrun init` in this project, or remove the hooks with `ironrun git uninstall-hooks`", err)
	}
	hits := hitsByAlias(secrets, text)
	if len(hits) == 0 {
		return nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "ironrun: BLOCKED — %s contains managed secret value(s):\n", where)
	for _, h := range hits {
		fmt.Fprintf(&sb, "  • %s (%s, %d match(es))\n", h.alias, h.placeholder, h.count)
	}
	sb.WriteString("Remove the value and use `ironrun run` / `ironrun env` to inject it instead.\n")
	sb.WriteString("(Values are never printed here — match the [REDACTED:<alias>:<sha8>] fingerprint to your vault.)")
	return fmt.Errorf("%s", sb.String())
}

func isZeroSha(sha string) bool {
	return sha != "" && strings.Trim(sha, "0") == ""
}
