package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Severity ranks a lint Finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarn
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarn:
		return "warn"
	default:
		return "info"
	}
}

// MarshalJSON emits the severity as its string name ("error"/"warn"/"info") so
// `lint --format json` is self-describing for CI tooling.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Finding is a single lint result.
type Finding struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	CmdID    string   `json:"command,omitempty"`
	Message  string   `json:"message"`
}

// interpreters are general-purpose runtimes that can execute arbitrary code, so
// their presence as argv[0] weakens the "fixed command" guarantee.
var interpreters = map[string]bool{
	"python": true, "python3": true, "node": true, "nodejs": true,
	"ruby": true, "perl": true, "php": true, "deno": true, "bun": true,
}

// evalFlags pass an inline program body to an interpreter.
var evalFlags = map[string]bool{
	"-c": true, "-e": true, "--eval": true, "-E": true,
}

const (
	longTTLThreshold = time.Hour
	secretSpreadMax  = 3
)

// Lint runs security-oriented static checks over a policy and returns findings.
// `validate` covers structural validity; Lint is the opinionated security review.
func Lint(f *File) []Finding {
	var out []Finding

	// Cross-command: which commands reference each secret ref (privilege creep).
	refCmds := map[string]map[string]bool{}
	for _, c := range f.Commands {
		for _, ref := range c.Env {
			if refCmds[ref] == nil {
				refCmds[ref] = map[string]bool{}
			}
			refCmds[ref][c.ID] = true
		}
	}

	for _, c := range f.Commands {
		hasSecrets := len(c.Env) > 0
		base := ""
		if len(c.Argv) > 0 {
			base = filepath.Base(c.Argv[0])
		}

		if IsShellString(c.Argv) {
			out = append(out, Finding{SeverityError, "SHELL_ARGV", c.ID,
				fmt.Sprintf("argv[0] %q is a shell; it will be denied at runtime. Wrap the command in a script file and call that instead.", c.Argv[0])})
		}

		if interpreters[base] {
			out = append(out, Finding{SeverityWarn, "INTERPRETER_ARBITRARY", c.ID,
				fmt.Sprintf("argv[0] %q is a general-purpose interpreter that can run arbitrary code; prefer a fixed script with a pinned argv.", base)})
			for _, a := range c.Argv[1:] {
				if evalFlags[a] {
					sev := SeverityWarn
					if hasSecrets {
						sev = SeverityError
					}
					out = append(out, Finding{sev, "INTERPRETER_EVAL", c.ID,
						fmt.Sprintf("argv passes an inline-eval flag (%q) to %s, letting the command body run arbitrary code with the injected secrets.", a, base)})
					break
				}
			}
		}

		switch {
		case c.TTL.Duration == 0:
			out = append(out, Finding{SeverityWarn, "NO_TTL", c.ID,
				"no ttl set; the command can run unbounded. Add e.g. `ttl: 10m`."})
		case c.TTL.Duration > longTTLThreshold && hasSecrets:
			out = append(out, Finding{SeverityInfo, "LONG_TTL_WITH_SECRETS", c.ID,
				fmt.Sprintf("ttl is %s with secrets injected; consider a shorter window.", c.TTL.Duration)})
		}

		if hasSecrets && !c.NoNetwork {
			out = append(out, Finding{SeverityWarn, "EGRESS_WITH_SECRETS", c.ID,
				"secrets are injected with network access open; an exfiltration path exists. Set `no_network: true` unless the command needs the network."})
		}

		if hasSecrets && c.MaxBytes == 0 {
			out = append(out, Finding{SeverityInfo, "NO_MAX_BYTES", c.ID,
				"no max_bytes cap with secrets injected; unbounded output enlarges the redaction surface. Consider setting `max_bytes`."})
		}

		for i, a := range c.Argv {
			if looksLikeSecret(a) {
				out = append(out, Finding{SeverityWarn, "SECRET_IN_ARGV", c.ID,
					fmt.Sprintf("argv[%d] looks like a hardcoded credential; put secrets in `env:` (injected and redacted), not argv (recorded verbatim).", i)})
			}
		}
	}

	// Privilege creep findings, emitted in a stable (sorted) order.
	var spread []string
	for ref, cmds := range refCmds {
		if len(cmds) > secretSpreadMax {
			spread = append(spread, ref)
		}
	}
	sort.Strings(spread)
	for _, ref := range spread {
		out = append(out, Finding{SeverityWarn, "SECRET_SPREAD", "",
			fmt.Sprintf("secret %q is referenced by %d commands; grant it only where needed to limit blast radius.", ref, len(refCmds[ref]))})
	}

	return out
}

// secretPrefixes are well-known credential token prefixes.
var secretPrefixes = []string{
	"sk_live_", "sk_test_", "ghp_", "gho_", "ghs_", "github_pat_",
	"xoxb-", "xoxp-", "AKIA", "ASIA", "AIza", "-----BEGIN",
}

func looksLikeSecret(s string) bool {
	for _, p := range secretPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
