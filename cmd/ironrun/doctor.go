package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

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
		Short: "Diagnose your ironrun setup (policy, environment, provider, commands)",
		Long: `Runs read-only checks against your ironrun setup:
  • the policy file parses and is a supported version
  • local environment metadata matches this project, is selected and unexpired,
    and contains required entry names (for policies using local entries)
  • the legacy secret provider is installed and authenticated where checkable
  • the redaction engine actually strips a known secret from output
  • each command's binary resolves on PATH

Exits non-zero if any check fails. Saved commands are not executed and no secret
values are resolved. Local vault access and decryption are not checked.`,
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

			// 2. Entry-backed policies need metadata, not a legacy provider's
			// passthrough health check. Do not use envset.Open here: it can open
			// native secure storage and migrate files.
			if f.UsesEnvironmentEntries() || f.EnvironmentSet == "active" {
				checkDoctorEnvironment(f, policyProjectRoot(policyPath), pass, fail, warn)
				warn("Secret values and vault access were not checked")
			}
			// Legacy providers can still supply inline env references, even in
			// a policy whose declared secrets use the local environment.
			if !f.UsesEnvironmentEntries() || f.Provider != "" {
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

type doctorMessage func(string, ...any)

func checkDoctorEnvironment(f *policy.File, root string, pass, fail, note doctorMessage) {
	needsEntries := false
	for _, command := range f.Commands {
		needsEntries = needsEntries || len(command.Secrets) > 0
	}
	if !needsEntries {
		pass("no saved commands require environment entries")
		return
	}
	note("Run environment repair commands from %q", root)
	meta, err := envset.InspectMetadata(root)
	switch {
	case os.IsNotExist(err):
		fail("environment metadata is missing; next: ironrun env init dev")
		return
	case errors.Is(err, envset.ErrProjectIdentityChanged):
		fail("project identity changed; restore the recorded checkout path and Git origin before retrying")
		return
	case err != nil:
		fail("environment metadata is unavailable: %v; restore valid .ironrun/environments.json from your backup", err)
		return
	}
	pass("project identity matches environment metadata")
	now := time.Now()
	repairSelection := func() {
		names := make([]string, 0, len(meta.Sets))
		for name, set := range meta.Sets {
			if set.Name == name && (set.ExpiresAt == nil || now.Before(*set.ExpiresAt)) && doctorValidName(name) && doctorPrintableArgument(name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			note("Next: %s", doctorEnvCommand("use", names[0]))
		} else {
			name := "dev"
			for i := 2; ; i++ {
				if _, exists := meta.Sets[name]; !exists {
					break
				}
				name = fmt.Sprintf("dev%d", i)
			}
			note("Next: %s; then %s", doctorEnvCommand("create", name), doctorEnvCommand("use", name))
		}
	}
	if meta.Active == "" {
		fail("no active environment is selected")
		repairSelection()
		return
	}
	selected, exists := meta.Sets[meta.Active]
	if !exists {
		fail("environment %q is missing", meta.Active)
		repairSelection()
		return
	}
	if selected.Name != meta.Active || !doctorValidName(meta.Active) {
		fail("selected environment metadata is invalid; restore its name and selection in .ironrun/environments.json from your backup")
		return
	}
	if selected.ExpiresAt != nil && !now.Before(*selected.ExpiresAt) {
		fail("environment %q has expired", meta.Active)
		repairSelection()
		return
	}
	pass("selected environment %q (unexpired)", meta.Active)
	entries := make(map[string]bool, len(selected.Entries))
	for _, entry := range selected.Entries {
		entries[entry.Name] = true
	}
	for _, command := range f.Commands {
		if len(command.Secrets) == 0 {
			continue
		}
		required := make(map[string]bool, len(command.Secrets))
		for _, alias := range command.Secrets {
			name := alias
			if !f.UsesEnvironmentEntries() {
				name = f.Secrets[alias].Env
			}
			required[name] = true
		}
		missing := make([]string, 0)
		for name := range required {
			if !entries[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			fail("command %q: entry %q is not configured in %q", command.ID, name, meta.Active)
			if !doctorPrintableArgument(meta.Active) {
				note("The environment name contains whitespace that cannot be safely displayed in a command; configure this entry through environment management instead of copying a shell command")
				continue
			}
			// Names need not be environment targets in v2 (file entry names
			// may contain dots or hyphens). Do not suggest an env-only command
			// that cannot create such an entry.
			fileEntry := false
			if !f.UsesEnvironmentEntries() {
				for _, alias := range command.Secrets {
					decl := f.Secrets[alias]
					fileEntry = fileEntry || decl.Env == name && decl.EffectiveKind() == "file"
				}
			}
			if !doctorEnvTarget(name) {
				note("The CLI cannot create this entry name as a target; choose an environment-variable name for this binding in the policy, then run %s (replace ENTRY_NAME)", doctorEnvCommand("set", meta.Active, "ENTRY_NAME"))
			} else if fileEntry {
				note("Configure a file entry with %s PATH (replace PATH with the owner-only source file)", doctorEnvCommand("file", meta.Active, name))
			} else {
				note("Next: %s", doctorEnvCommand("set", meta.Active, name))
			}
		}
		if len(missing) == 0 {
			pass("command %q: required entry names are configured", command.ID)
		}
	}
}

// Match the environment API's name validation: surrounding whitespace is
// ignored when validating, but preserved as part of the stored name.
func doctorValidName(name string) bool {
	return doctorSafeName(strings.TrimSpace(name))
}

// Names with printable ASCII spaces can be quoted in copyable commands. Other
// surrounding whitespace is valid storage metadata but needs manual recovery;
// it must never be emitted as terminal control characters in a command.
func doctorPrintableArgument(name string) bool {
	for _, r := range name {
		if r < ' ' || r > '~' {
			return false
		}
	}
	return true
}

func doctorSafeName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func doctorEnvTarget(name string) bool {
	for i, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return name != ""
}

func doctorEnvCommand(action string, args ...string) string {
	prefix := "ironrun env " + action
	quoted := make([]string, len(args))
	needsTerminator := false
	for i, arg := range args {
		if strings.HasPrefix(arg, "-") {
			needsTerminator = true
		}
		quoted[i] = arg
		if !doctorSafeName(arg) {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
	}
	if needsTerminator {
		prefix += " --"
	}
	return prefix + " " + strings.Join(quoted, " ")
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
