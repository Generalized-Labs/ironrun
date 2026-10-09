package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/scrub"
	"github.com/generalized-labs/ironrun/internal/shellguard"
)

// historyCmd: ironrun history — shell history secret cleanup.
func historyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "history",
		Short: "Purge managed secret values from shell history files",
	}
	c.AddCommand(historyPurgeCmd())
	return c
}

// historyPurgeCmd: ironrun history purge — exact-value (+encoded variants)
// cleanup of bash/zsh/fish history files. Dry-run by default: lists files and
// the lines that would be dropped. --apply rewrites each touched file
// atomically with no plaintext backup (a backup would re-persist the secrets).
func historyPurgeCmd() *cobra.Command {
	var apply bool
	var shells []string
	c := &cobra.Command{
		Use:   "purge",
		Short: "Purge vault values from shell history files (dry-run by default)",
		Long: `Scans bash, zsh and fish history files for exact vault values and their
encoded variants (base64, base64-url, percent-encoding) and drops matching
lines — zero false positives, because ironrun knows the exact values.

Safety:
  • dry-run by default: reports per-file line counts, changes nothing
  • --apply rewrites each touched file atomically (temp file + rename) with
    NO plaintext backup kept — a backup would re-persist the purged secrets;
    re-running is a no-op and also removes any stale .ironrun.bak`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			secrets, err := loadActiveSecrets()
			if err != nil {
				return err
			}
			m := scrub.NewMatcher(secrets)
			files := shellguard.HistoryFiles()
			if len(shells) > 0 {
				want := map[string]bool{}
				for _, s := range shells {
					want[strings.ToLower(s)] = true
				}
				var filtered []shellguard.HistoryFile
				for _, f := range files {
					if want[f.Shell] {
						filtered = append(filtered, f)
					}
				}
				files = filtered
			}
			res, err := shellguard.Purge(m, files, apply)
			if err != nil {
				return err
			}
			mode := map[bool]string{true: "APPLY", false: "dry-run"}[apply]
			fmt.Fprintf(out, "ironrun history purge (%s)\n\n", mode)
			for _, f := range res.Files {
				switch {
				case f.Missing:
					fmt.Fprintf(out, "  %s (%s): no history file\n", f.Path, f.Shell)
				case f.MatchedLines == 0:
					fmt.Fprintf(out, "  %s (%s): clean\n", f.Path, f.Shell)
				case !apply:
					fmt.Fprintf(out, "  %s (%s): %d line(s) would be dropped\n", f.Path, f.Shell, f.MatchedLines)
				default:
					fmt.Fprintf(out, "  %s (%s): dropped %d line(s), rewritten\n", f.Path, f.Shell, f.MatchedLines)
				}
			}
			fmt.Fprintf(out, "\n%d matched line(s) across %d file(s), %d rewritten\n", res.Matched, len(res.Files), res.Rewrote)
			if !apply && res.Matched > 0 {
				fmt.Fprintln(out, "Re-run with --apply to back up and rewrite.")
			}
			if apply && res.Rewrote > 0 {
				fmt.Fprintln(out, "Note: shells already running keep their in-memory history and will")
				fmt.Fprintln(out, "re-append it on exit — restart them (or run `history -c`) so the")
				fmt.Fprintln(out, "purged lines stay gone.")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&apply, "apply", false, "back up and rewrite history files (default is dry-run)")
	c.Flags().StringSliceVar(&shells, "shell", nil, "limit to shell(s): bash, zsh, fish")
	return c
}
