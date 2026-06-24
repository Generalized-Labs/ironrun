package action_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/generalized-labs/ironrun/action"
)

// TestMain keeps these in-process sealed runs from writing the real
// ~/.ironrun/audit.jsonl.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ironrun-action-audit")
	if err == nil {
		os.Setenv("IRONRUN_AUDIT_PATH", filepath.Join(dir, "audit.jsonl"))
	} else {
		os.Setenv("IRONRUN_AUDIT", "off")
	}
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

func TestRun_MissingCommandID(t *testing.T) {
	os.Unsetenv("INPUT_COMMAND_ID")
	os.Unsetenv("INPUT_POLICY")
	code := action.Run()
	if code == 0 {
		t.Error("expected non-zero exit when command_id missing")
	}
}

func TestRun_MissingPolicy(t *testing.T) {
	t.Setenv("INPUT_COMMAND_ID", "test")
	t.Setenv("INPUT_POLICY", "/tmp/does-not-exist-ironrun.yml")
	code := action.Run()
	if code == 0 {
		t.Error("expected non-zero exit when policy missing")
	}
}

func TestRun_ValidEcho(t *testing.T) {
	// Write a temp policy.
	policyYAML := `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello-from-action]
`
	f, err := os.CreateTemp("", "ironrun-action-test-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(policyYAML)
	f.Close()

	t.Setenv("INPUT_COMMAND_ID", "greet")
	t.Setenv("INPUT_POLICY", f.Name())
	os.Unsetenv("GITHUB_WORKSPACE")

	code := action.Run()
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}
