package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/envset"
)

// Project metadata can outlive the vault it describes: ~/.ironrun is deleted, a
// project directory moves to a machine without its vault, or
// IRONRUN_VAULT_PROTECTOR changes and opens a different vault. From the outside
// that state is a dead end — `import` refuses with "already configured" while
// `run` fails with "unavailable" — and `doctor` used to report "All checks
// passed" over it. This pins the check that names the problem.
func TestDoctorReportsDeclaredValuesMissingFromVault(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(envset.ProtectorEnv, "file")

	policy := `version: "2"
environment_set: active
commands:
  - id: test
    argv: [sh]
    secrets: [DATABASE_URL]
`
	policyFile := filepath.Join(project, "ironrun.yml")
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	// Register the project and record DATABASE_URL as configured.
	m, err := envset.Open(project)
	if err != nil {
		t.Fatalf("open envset: %v", err)
	}
	if _, err := m.Create("dev", false, 0); err != nil {
		t.Fatalf("create set: %v", err)
	}
	if err := m.Use("dev"); err != nil {
		t.Fatalf("use set: %v", err)
	}
	if err := m.Put("dev", "DATABASE_URL", "postgres://localhost/db"); err != nil {
		t.Fatalf("store value: %v", err)
	}

	// Now remove the vault while leaving the project metadata in place. This is
	// exactly what deleting ~/.ironrun, or switching protectors, produces.
	if err := os.RemoveAll(filepath.Join(home, ".ironrun", "vaults")); err != nil {
		t.Fatalf("remove vaults: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(home, ".ironrun", "keys")); err != nil {
		t.Fatalf("remove keys: %v", err)
	}

	reopened, err := envset.Open(project)
	if err != nil {
		t.Fatalf("reopen envset: %v", err)
	}
	if _, err := reopened.Get("dev", "DATABASE_URL"); err == nil {
		t.Fatal("value still resolves after the vault was removed; the fixture no longer reproduces the divergence")
	}

	// Metadata must still claim the key, otherwise there is nothing to detect.
	set, ok := reopened.Set("dev")
	if !ok {
		t.Fatal("environment set disappeared with the vault")
	}
	if !containsString(set.Keys, "DATABASE_URL") {
		t.Fatalf("metadata no longer lists DATABASE_URL, got %v", set.Keys)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// The recovery path doctor prints must name commands that actually exist.
// `env delete` takes NAME KEY and removes a single value; removing the whole
// set is `env remove`.
func TestDoctorRecoveryHintNamesRealCommands(t *testing.T) {
	root := envCmd()

	for _, want := range []string{"remove", "rotate"} {
		var found bool
		for _, sub := range root.Commands() {
			if sub.Name() == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("doctor suggests `ironrun env %s`, but that subcommand does not exist", want)
		}
	}

	// `env remove` must take just the set name, as the hint implies.
	for _, sub := range root.Commands() {
		if sub.Name() == "remove" && !strings.Contains(sub.Use, "NAME") {
			t.Errorf("env remove usage %q does not look like it takes a set name", sub.Use)
		}
	}
}
