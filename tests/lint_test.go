package tests

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestCLI_Lint_CleanPolicyPasses(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: build
    argv: [go, build, ./...]
    ttl: 5m
    no_network: true
`)
	out, err := exec.Command(cliBin, "--policy", policy, "lint").CombinedOutput()
	if err != nil {
		t.Fatalf("lint on clean policy should exit 0: %v\n%s", err, out)
	}
}

func TestCLI_Lint_ShellArgvFails(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: x
    argv: [bash, -c, "echo hi"]
    ttl: 5s
`)
	out, err := exec.Command(cliBin, "--policy", policy, "lint").CombinedOutput()
	if err == nil {
		t.Fatalf("lint should exit non-zero for shell argv, got success: %s", out)
	}
	if !strings.Contains(string(out), "SHELL_ARGV") {
		t.Errorf("expected SHELL_ARGV in output, got: %s", out)
	}
}

func TestCLI_Lint_JSONFormat(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: x
    argv: [go, test]
    ttl: 5m
    env:
      DB: localvalue
`)
	out, err := exec.Command(cliBin, "--policy", policy, "lint", "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("lint --format json (warn-only policy) should exit 0: %v\n%s", err, out)
	}
	var findings []map[string]any
	if e := json.Unmarshal(out, &findings); e != nil {
		t.Fatalf("lint json output is not valid JSON: %v\n%s", e, out)
	}
	if len(findings) == 0 {
		t.Errorf("expected at least one finding (egress with secrets), got none")
	}
}

func TestCLI_Lint_StrictPromotesWarnings(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: x
    argv: [go, test]
    ttl: 5m
    env:
      DB: localvalue
`)
	// Warn-only policy passes normally.
	if _, err := exec.Command(cliBin, "--policy", policy, "lint").CombinedOutput(); err != nil {
		t.Fatalf("non-strict lint with only warnings should exit 0: %v", err)
	}
	// --strict promotes warnings to a non-zero exit.
	out, err := exec.Command(cliBin, "--policy", policy, "lint", "--strict").CombinedOutput()
	if err == nil {
		t.Fatalf("strict lint with warnings should exit non-zero, got success: %s", out)
	}
}
