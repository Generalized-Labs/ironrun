package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/redact"
	"github.com/generalized-labs/ironrun/internal/runner"
)

// doctorCmd: ironrun doctor — read-only diagnosis of an ironrun setup.
func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose your ironrun setup (policy, provider, redaction, commands)",
		Long: `Runs read-only checks against your ironrun setup:
  • the policy file parses and is a supported version
  • the configured secret provider is installed and authenticated
  • the redaction engine actually strips a known secret from output
  • each command's binary resolves on PATH

Exits non-zero if any check fails. Nothing is executed and no secrets are resolved.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			var failed bool
			pass := func(format string, a ...any) { fmt.Fprintf(out, "  ✓ "+format+"\n", a...) }
			fail := func(format string, a ...any) { failed = true; fmt.Fprintf(out, "  ✗ "+format+"\n", a...) }
			warn := func(format string, a ...any) { fmt.Fprintf(out, "  ○ "+format+"\n", a...) }

			fmt.Fprintln(out, "ironrun doctor")
			fmt.Fprintln(out)

			// 1. Policy file.
			f, err := policy.Load(policyPath)
			if err != nil {
				fail("%s: %v", policyPath, err)
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Fix the policy file and re-run `ironrun doctor`. (New project? run `ironrun init`.)")
				os.Exit(1)
			}
			pass("%s valid (v%s, %d command(s))", policyPath, f.Version, len(f.Commands))

			// 2. Provider: installed + authenticated where checkable.
			p, perr := provider.New(f.Provider)
			switch {
			case perr != nil:
				fail("provider %q: %v", f.Provider, perr)
			default:
				if hc, ok := p.(provider.HealthChecker); ok {
					if err := hc.Check(); err != nil {
						fail("provider %s: %v", p.Name(), err)
					} else {
						pass("provider %s (ready)", p.Name())
					}
				} else {
					pass("provider %s (no external CLI required)", p.Name())
				}
			}

			// 3. Redaction self-test.
			if err := redactionSelfTest(); err != nil {
				fail("redaction self-test: %v", err)
			} else {
				pass("redaction self-test passed")
			}

			// 4. Each command's binary resolves.
			for _, c := range f.Commands {
				switch {
				case len(c.Argv) == 0:
					fail("command %q: empty argv", c.ID)
				case policy.IsShellString(c.Argv):
					warn("command %q: %v is a shell invocation — denied at runtime", c.ID, c.Argv)
				default:
					bin := c.Argv[0]
					if _, err := exec.LookPath(bin); err != nil {
						fail("command %q: %q not found on PATH", c.ID, bin)
					} else {
						pass("command %q: %q resolves", c.ID, bin)
					}
				}
			}

			fmt.Fprintln(out)
			if failed {
				fmt.Fprintln(out, "Some checks failed. See above.")
				os.Exit(1)
			}
			fmt.Fprintln(out, "All checks passed.")
			return nil
		},
	}
}

// redactionSelfTest writes a known secret — both as a literal and base64-encoded —
// through the redactor (registering the same variant set the runner uses) and
// confirms neither form reaches the output.
func redactionSelfTest() error {
	const secret = "ironrun-doctor-canary-9f3a1c"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	var buf strings.Builder
	w := redact.New(&buf, runner.SecretVariants(secret), 0)
	if _, err := w.Write([]byte("literal " + secret + " encoded " + b64 + " end")); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	got := buf.String()
	if strings.Contains(got, secret) {
		return fmt.Errorf("literal secret leaked through redactor: %q", got)
	}
	if strings.Contains(got, b64) {
		return fmt.Errorf("base64-encoded secret leaked through redactor: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		return fmt.Errorf("expected [REDACTED] in output, got %q", got)
	}
	return nil
}
