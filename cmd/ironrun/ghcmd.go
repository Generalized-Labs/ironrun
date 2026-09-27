package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/ghprotect"
)

// ghCmd: ironrun gh — GitHub-side secret-scanning hardening via the gh CLI.
func ghCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "gh",
		Short: "Harden GitHub repos against secret leaks via the gh CLI",
	}
	c.AddCommand(ghProtectCmd())
	return c
}

// ghProtectCmd: ironrun gh protect — one command that enables GitHub secret
// scanning + push protection, installs custom push-protection patterns, and
// surfaces the bypass-policy checklist.
//
// Fails LOUDLY when gh is missing or not authenticated — before doing
// anything else, in both dry-run and apply modes. --dry-run prints the exact
// `gh api` calls without executing them.
func ghProtectCmd() *cobra.Command {
	var repoFlag, orgFlag string
	var patternFlags []string
	var dryRun bool
	c := &cobra.Command{
		Use:   "protect",
		Short: "Enable secret scanning + push protection, install custom patterns",
		Long: `One command that hardens a GitHub repository (or every repository in an
org) against secret leaks, via the gh CLI:

  1. Enables secret scanning AND push protection on the repo.
  2. With --org: also sets the org defaults so new repositories inherit both,
     and applies step 1 to every existing repo in the org.
  3. With --pattern name=REGEX (repeatable): publishes custom push-protection
     patterns for your internal token shapes. Patterns must be RE2-safe
     (no lookarounds) and simple — GitHub uses a Hyperscan engine.

Custom patterns land UNPUBLISHED — GitHub exposes no API to publish them or
to enable push protection per pattern, so the command tells you exactly what
to click. The standing bypass policy ("allow bypasses" / "require bypass
reason") likewise has no public REST endpoint and is surfaced as an explicit
manual checklist rather than an invented call.

Requires the gh CLI, authenticated, with admin rights on the target repo(s).
Custom patterns additionally require GitHub Secret Protection on private
repositories (paid plan).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			gh, err := ghprotect.Preflight()
			if err != nil {
				return err
			}
			var patterns []ghprotect.Pattern
			for _, p := range patternFlags {
				name, regex, ok := strings.Cut(p, "=")
				if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(regex) == "" {
					return fmt.Errorf("--pattern must be name=REGEX, got %q", p)
				}
				pat := ghprotect.Pattern{Name: strings.TrimSpace(name), Regex: strings.TrimSpace(regex)}
				if err := ghprotect.ValidatePattern(pat); err != nil {
					return err
				}
				patterns = append(patterns, pat)
			}
			type target struct{ owner, repo string }
			var targets []target
			var calls []ghprotect.Call
			if orgFlag != "" {
				calls = append(calls, ghprotect.OrgDefaults(orgFlag))
				repos, err := ghprotect.ListOrgRepos(gh, orgFlag)
				if err != nil {
					return err
				}
				if len(repos) == 0 {
					return fmt.Errorf("org %q has no repositories visible to this token", orgFlag)
				}
				for _, full := range repos {
					parts := strings.SplitN(full, "/", 2)
					targets = append(targets, target{parts[0], parts[1]})
				}
			} else {
				owner, repo := repoFlag, ""
				if owner != "" {
					parts := strings.SplitN(owner, "/", 2)
					if len(parts) != 2 {
						return fmt.Errorf("--repo must be owner/name, got %q", owner)
					}
					owner, repo = parts[0], parts[1]
				} else {
					owner, repo, err = ghprotect.CurrentRepo(gh)
					if err != nil {
						return err
					}
				}
				targets = append(targets, target{owner, repo})
			}
			for _, t := range targets {
				calls = append(calls, ghprotect.EnableRepoScanning(t.owner, t.repo))
				if len(patterns) > 0 {
					pc, err := ghprotect.CreateCustomPatterns(t.owner, t.repo, patterns)
					if err != nil {
						return err
					}
					calls = append(calls, pc)
				}
			}
			mode := map[bool]string{true: "dry-run", false: "APPLY"}[dryRun]
			fmt.Fprintf(out, "ironrun gh protect (%s) — %d call(s)\n\n", mode, len(calls))
			for i, call := range calls {
				fmt.Fprintf(out, "# %d\n%s\n\n", i+1, call.Render())
				if dryRun {
					continue
				}
				if err := ghprotect.Exec(gh, call); err != nil {
					return fmt.Errorf("call %d failed, aborting: %w", i+1, err)
				}
				fmt.Fprintf(out, "  → ok\n\n")
			}
			if len(patterns) > 0 {
				fmt.Fprintln(out, "ACTION REQUIRED (no API exists — UI only):")
				fmt.Fprintln(out, "  1. Open each repo's Settings → Code security → Custom patterns.")
				fmt.Fprintln(out, "  2. Dry-run the new pattern(s) against the repo to estimate false positives.")
				fmt.Fprintln(out, "  3. Publish each pattern, then enable push protection for it.")
				fmt.Fprintln(out)
			}
			fmt.Fprintln(out, "Bypass policy (no public REST endpoint — configure manually):")
			for _, item := range ghprotect.BypassPolicyChecklist() {
				fmt.Fprintf(out, "  • %s\n", item)
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoFlag, "repo", "", "target as owner/name (default: repo of the current checkout)")
	c.Flags().StringVar(&orgFlag, "org", "", "harden every repo in this org + set org defaults for new repos")
	c.Flags().StringArrayVar(&patternFlags, "pattern", nil, "custom pattern as name=REGEX (repeatable; RE2-safe, no lookarounds)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "print the exact gh api calls without executing them")
	return c
}
