package action_test

import (
	"os"
	"testing"

	"github.com/generalized-labs/ironrun/action"
)

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
