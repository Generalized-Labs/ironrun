package main

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/scrub"
)

// loadActiveSecrets returns every value in the active environment set as
// alias/value pairs. Read-only: it never writes to the vault or the project.
// Values stay in memory only for the duration of the matching pass.
func loadActiveSecrets() ([]scrub.Secret, error) {
	m, err := openEnvManager()
	if err != nil {
		return nil, fmt.Errorf("open ironrun project: %w (run `ironrun init` in a project directory first)", err)
	}
	s, err := m.Active()
	if err != nil {
		return nil, fmt.Errorf("no active environment set: %w", err)
	}
	out := setSecrets(m, s, nil)
	if len(out) == 0 {
		return nil, fmt.Errorf("active environment set %q holds no values to match against", s.Name)
	}
	return out, nil
}

// loadAllSecrets is loadActiveSecrets over every unexpired environment set:
// the git hooks must block a prod value committed while dev is active.
func loadAllSecrets() ([]scrub.Secret, error) {
	m, err := openEnvManager()
	if err != nil {
		return nil, fmt.Errorf("open ironrun project: %w (run `ironrun init` in a project directory first)", err)
	}
	return allSetSecrets(m)
}

func allSetSecrets(m *envset.Manager) ([]scrub.Secret, error) {
	var out []scrub.Secret
	for _, name := range m.Names() {
		if s, ok := m.Set(name); ok && !m.Expired(s) {
			out = setSecrets(m, s, out)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no environment set holds values to match against")
	}
	return out, nil
}

// setSecrets appends set s's non-empty values to out, skipping an alias/value
// pair already present (the same value stored in two sets).
func setSecrets(m *envset.Manager, s envset.Set, out []scrub.Secret) []scrub.Secret {
	for _, e := range s.Entries {
		var v string
		switch e.Kind {
		case envset.EntryFile:
			b, gerr := m.GetBytes(s.Name, e.Name)
			if gerr != nil {
				fmt.Fprintf(os.Stderr, "ironrun: warning: skipping unreadable entry %q: %v (scan continues with the remaining values)\n", e.Name, gerr)
				continue
			}
			v = string(b)
		default:
			var err error
			v, err = m.Get(s.Name, e.Name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ironrun: warning: skipping unreadable entry %q: %v (scan continues with the remaining values)\n", e.Name, err)
				continue
			}
		}
		if v == "" || slices.Contains(out, scrub.Secret{Alias: e.Name, Value: v}) {
			continue
		}
		out = append(out, scrub.Secret{Alias: e.Name, Value: v})
	}
	return out
}

// aliasHit is one alias matched inside scanned text, with its safe summary.
type aliasHit struct {
	alias       string
	placeholder string
	count       int
}

// hitsByAlias scans text once per alias so block messages can name exactly
// which aliases fired — without ever printing a value.
func hitsByAlias(secrets []scrub.Secret, text string) []aliasHit {
	var hits []aliasHit
	for _, s := range secrets {
		m := scrub.NewMatcher([]scrub.Secret{s})
		if len(m.Secrets()) == 0 {
			continue // skipped (too short etc.)
		}
		if _, n := m.Redact(text); n > 0 {
			hits = append(hits, aliasHit{alias: s.Alias, placeholder: scrub.Placeholder(s.Alias, s.Value), count: n})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].alias < hits[j].alias })
	return hits
}

// agentScrubCmd: ironrun agent-scrub — exact-value transcript scrubber.
//
// Dry-run by default: lists every store file containing managed values (and
// how many matches each holds) without touching anything. --apply rewrites
// matches to [REDACTED:<alias>:<sha8>] atomically and idempotently.
func agentScrubCmd() *cobra.Command {
	var apply bool
	var onlyStores []string
	c := &cobra.Command{
		Use:   "agent-scrub",
		Short: "Scrub vault values from AI agent session logs (dry-run by default)",
		Long: `Scans the session stores of the six supported agent CLIs — Claude Code,
Codex, GitHub Copilot CLI, Gemini CLI, Cursor and Windsurf — for exact vault
values and their encoded variants (base64, base64-url, percent-encoding),
and replaces matches with [REDACTED:<alias>:<sha8>].

Values come from the active environment set; matching is exact, so false
positives are near zero.

Safety:
  • dry-run by default: lists files and match counts, changes nothing
  • --apply rewrites files atomically (temp file + rename), idempotently —
    a second run finds nothing left to replace
  • only files under the six known store roots are ever touched
  • SQLite/opaque stores (Cursor/Windsurf state.vscdb, Copilot
    session-store.db, Windsurf .pb bundles) cannot be rewritten safely and
    are reported as skipped, never modified`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			secrets, err := loadActiveSecrets()
			if err != nil {
				return err
			}
			roots := scrub.KnownRoots()
			if len(onlyStores) > 0 {
				want := map[string]bool{}
				for _, s := range onlyStores {
					want[strings.ToLower(s)] = true
				}
				var filtered []scrub.StoreRoot
				for _, r := range roots {
					if want[r.Name] {
						filtered = append(filtered, r)
					}
				}
				if len(filtered) == 0 {
					return fmt.Errorf("no known store matches --store %q (claude, codex, copilot, gemini, cursor, windsurf)", strings.Join(onlyStores, ","))
				}
				roots = filtered
			}
			m := scrub.NewMatcher(secrets)
			if m.Skipped() > 0 {
				fmt.Fprintf(out, "note: %d alias(es) skipped (empty or shorter than %d chars)\n\n", m.Skipped(), scrub.MinSecretLen)
			}
			res, err := scrub.Scrub(m, roots, apply)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "ironrun agent-scrub (%s)\n\n", map[bool]string{true: "APPLY", false: "dry-run"}[apply])
			for _, r := range roots {
				var matched []scrub.FileResult
				var skipped []scrub.FileResult
				for _, f := range res.Files {
					if f.Store != r.Name || f.Matches == 0 {
						continue
					}
					matched = append(matched, f)
				}
				for _, f := range res.Files {
					if f.Store == r.Name && f.Skipped {
						skipped = append(skipped, f)
					}
				}
				if len(matched) == 0 && len(skipped) == 0 {
					continue
				}
				fmt.Fprintf(out, "%s:\n", r.Name)
				for _, f := range matched {
					status := "would rewrite"
					if f.Rewritten {
						status = "rewrote"
					}
					fmt.Fprintf(out, "  %s — %d match(es) (%s)\n", f.Path, f.Matches, status)
				}
				for _, f := range skipped {
					fmt.Fprintf(out, "  %s — skipped: %s\n", f.Path, f.SkipReason)
				}
			}
			fmt.Fprintf(out, "\nscanned %d file(s), %d with matches, %d rewritten, %d skipped\n",
				res.Scanned, res.Matched, res.Rewrote, res.SkippedN)
			if !apply && res.Matched > 0 {
				fmt.Fprintln(out, "Re-run with --apply to rewrite the matches.")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&apply, "apply", false, "rewrite matched files (default is dry-run)")
	c.Flags().StringSliceVar(&onlyStores, "store", nil, "limit to store(s): claude, codex, copilot, gemini, cursor, windsurf")
	return c
}
