package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/redact"
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
  • every value the policy declares can be read back from the vault
  • each command's binary resolves on PATH

Exits non-zero if any check fails. No command is executed. Declared values are
decrypted in-process only to confirm they are readable, and are never printed,
logged, or written anywhere.`,
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

			// 4. Declared environment entries actually resolve.
			//
			// Project metadata can list keys the vault cannot produce: after
			// ~/.ironrun is deleted, after a project directory moves to a
			// machine without its vault, or after switching
			// IRONRUN_VAULT_PROTECTOR, which opens a different vault. That
			// state is a dead end from the outside — `import` refuses with
			// "already configured" while `run` fails with "unavailable" — so
			// naming it here is the only thing that points at a way out.
			if declared := policyKeys(f); len(declared) > 0 {
				switch m, mErr := openEnvManager(); {
				case mErr != nil:
					warn("environment sets unavailable: %v", mErr)
				case m.Meta.Active == "":
					warn("no active environment set; `ironrun new dev` creates one")
				default:
					active := m.Meta.Active
					var missing []string
					for _, key := range declared {
						// Values are decrypted in-process only to confirm they
						// are readable. Nothing is printed, logged, or returned.
						var getErr error
						if entry, typed := m.Entry(active, key); typed && entry.Kind == envset.EntryFile {
							_, getErr = m.GetBytes(active, key)
						} else {
							_, getErr = m.Get(active, key)
						}
						if getErr != nil {
							missing = append(missing, key)
						}
					}
					if len(missing) > 0 {
						fail("environment %q: %d of %d declared value(s) missing from the vault: %s",
							active, len(missing), len(declared), strings.Join(missing, ", "))
						warn("the policy and project metadata expect these, but this vault cannot produce them")
						warn("if you set %s, unset it — a different protector opens a different vault", envset.ProtectorEnv)
						warn("otherwise re-enter one value with `ironrun env rotate %s <KEY>`,", active)
						warn("or start over with `ironrun env remove %s` and re-import", active)
					} else {
						pass("environment %q: all %d declared value(s) resolve", active, len(declared))
					}
				}
			}

			// 5. Each command's binary resolves.
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

// redactionSelfTest writes a known secret through the redactor and confirms the
// value never reaches the output and is replaced with the placeholder.
func redactionSelfTest() error {
	const secret = "ironrun-doctor-canary-9f3a1c"
	var buf strings.Builder
	w := redact.New(&buf, []string{secret}, 0)
	if _, err := w.Write([]byte("before " + secret + " after")); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	got := buf.String()
	if strings.Contains(got, secret) {
		return fmt.Errorf("secret value leaked through redactor: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		return fmt.Errorf("expected [REDACTED] in output, got %q", got)
	}
	return nil
}
