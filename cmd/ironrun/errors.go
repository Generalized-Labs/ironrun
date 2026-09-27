package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Teaching errors: every failure the CLI surfaces gets a what/why/fix hint
// appended (the clig.dev shape from the DX spec: cause, fix, next command).
// This is the single choke point — main() routes all Execute() errors here —
// so internal packages keep their stable sentinel strings and the CLI layer
// translates them into actionable guidance. Nothing here changes behavior;
// it only adds text after the error line.

// reportError prints err and, when a known failure shape matches, a
// remediation hint. Unknown errors print bare, as before.
func reportError(root *cobra.Command, err error) {
	msg := err.Error()
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)

	// Unknown command: suggest the closest registered command ("Did you mean").
	if name, ok := unknownCommandName(msg); ok {
		if sug := suggestCommand(root, name); sug != "" {
			fmt.Fprintf(os.Stderr, "\nDid you mean `ironrun %s`?\n", sug)
		}
		return
	}
	if hint := errorHint(msg); hint != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", hint)
	}
}

// unknownCommandName extracts the attempted name from cobra's
// `unknown command "X" for "ironrun"` error.
func unknownCommandName(msg string) (string, bool) {
	const prefix = `unknown command "`
	if !strings.HasPrefix(msg, prefix) {
		return "", false
	}
	rest := msg[len(prefix):]
	if i := strings.Index(rest, `"`); i > 0 {
		return rest[:i], true
	}
	return "", false
}

// suggestCommand returns the closest registered top-level command name to a
// typo, or "" when nothing is close enough to suggest. It never auto-runs.
func suggestCommand(root *cobra.Command, name string) string {
	best, bestDist := "", -1
	for _, c := range root.Commands() {
		if !c.IsAvailableCommand() {
			continue
		}
		d := levenshtein(strings.ToLower(name), c.Name())
		if bestDist < 0 || d < bestDist {
			best, bestDist = c.Name(), d
		}
	}
	// Suggest only on a genuinely close typo: at most ~1 in 3 chars wrong,
	// minimum 1, maximum 3 edits.
	allow := len(name) / 3
	if allow < 1 {
		allow = 1
	}
	if allow > 3 {
		allow = 3
	}
	if bestDist >= 0 && bestDist <= allow {
		return best
	}
	return ""
}

// levenshtein is the optimal-string-alignment distance: adjacent
// transpositions ("rnu"→"run") cost 1, like a single typo should.
// Command names are tiny, so a full matrix is clearer than a rolling array.
func levenshtein(a, b string) int {
	m, n := len(a), len(b)
	d := make([][]int, m+1)
	for i := range d {
		d[i] = make([]int, n+1)
		d[i][0] = i
	}
	for j := 1; j <= n; j++ {
		d[0][j] = j
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1) // adjacent transposition
			}
		}
	}
	return d[m][n]
}

// errorHint matches stable internal error strings to remediation text.
// Order matters: specific shapes first. Messages that already carry a
// backticked `ironrun ...` remediation get no appended hint.
func errorHint(msg string) string {
	if strings.Contains(msg, "`ironrun ") {
		return ""
	}
	switch {
	case strings.Contains(msg, "unknown flag:"),
		strings.Contains(msg, "unknown shorthand flag:"):
		return "That flag doesn't exist. See what this command accepts:\n  ironrun --help   (or: ironrun <command> --help)"
	case strings.Contains(msg, "accepts") && strings.Contains(msg, "arg(s)"):
		return "Wrong number of arguments. Check the usage:\n  ironrun <command> --help"
	case strings.Contains(msg, "policy file not found"):
		return "No ironrun.yml here. New project? Start with:\n  ironrun init\nOtherwise point at your policy explicitly:\n  ironrun --policy PATH <command>"
	case strings.Contains(msg, "policy file malformed"),
		strings.Contains(msg, "policy: unsupported version"),
		strings.Contains(msg, "policy: no commands defined"),
		strings.Contains(msg, "policy: bad duration"):
		return "The policy file has a structural problem (details above). Validate it without running anything:\n  ironrun validate --policy PATH\nThen run the security checks:\n  ironrun lint"
	case strings.Contains(msg, "not found in policy"):
		return "That command ID isn't defined in this project's ironrun.yml. List the allowed commands:\n  ironrun validate\n(IDs come from the `commands:` section — agents may only run those.)"
	case strings.Contains(msg, "no active environment"):
		return "No environment is selected for this project. Create one, then store the value:\n  ironrun new NAME\n  ironrun env set KEY   (masked prompt — never pass values as flags)"
	case strings.Contains(msg, "environment set") && strings.Contains(msg, "not found"):
		return "That environment doesn't exist here. List the ones you have:\n  ironrun env list"
	case strings.Contains(msg, "not found in"):
		// provider: secret %q not found in <backend>
		return "That secret isn't stored yet. Add it with a masked prompt (never as a flag):\n  ironrun env set KEY"
	case strings.Contains(msg, "secret resolution failed"):
		return "A secret referenced by ironrun.yml isn't available for this run. Either store it:\n  ironrun env set KEY\nor remove it from the command's `secrets:` list in ironrun.yml."
	case strings.Contains(msg, "provider not configured"):
		return "No secret provider is configured for this project. Diagnose the setup:\n  ironrun doctor\n(New project? `ironrun init` sets up the local encrypted vault.)"
	case strings.Contains(msg, "ttl exceeds maximum"):
		return "Leases are TTL-capped by policy. Request a shorter TTL, or ask the project owner to raise the cap."
	case strings.Contains(msg, "environment") && strings.Contains(msg, "is unavailable"):
		return "That environment is missing or expired. List what's available:\n  ironrun env list"
	}
	return ""
}
