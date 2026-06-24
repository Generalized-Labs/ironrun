package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cliBin is the path to the compiled ironrun binary built once in TestMain.
// NOTE: exfiltration_test.go already declares no TestMain, so we add one here.
var cliBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ironrun-cli-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	cliBin = filepath.Join(dir, "ironrun")
	// Keep sealed runs in these tests from writing the real ~/.ironrun/audit.jsonl
	// (the spawned binary inherits this env).
	os.Setenv("IRONRUN_AUDIT_PATH", filepath.Join(dir, "audit.jsonl"))
	build := exec.Command("go", "build", "-o", cliBin, "./cmd/ironrun")
	build.Dir = ".." // repo root (tests/ package runs with wd = tests/ dir)
	if out, berr := build.CombinedOutput(); berr != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", berr, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// writeTempPolicyFile writes YAML content to a temp file and returns its path.
func writeTempPolicyFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "ironrun-cli-policy-*.yml")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatalf("write policy: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// exitCode extracts the process exit code from an *exec.ExitError.
// Returns 0 for nil error (success), or the raw exit code.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCLI_Version(t *testing.T) {
	out, err := exec.Command(cliBin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version exited non-zero: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "ironrun") {
		t.Errorf("expected 'ironrun' in version output, got: %q", string(out))
	}
}

func TestCLI_Run_Echo(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`)
	cmd := exec.Command(cliBin, "--policy", policy, "run", "greet")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run greet exited non-zero: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("expected 'hello' in output, got: %q", string(out))
	}
}

func TestCLI_Run_UnknownCommand(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`)
	cmd := exec.Command(cliBin, "--policy", policy, "run", "no-such-command")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for unknown command, got success\noutput: %s", out)
	}
}

func TestCLI_Run_BadPolicy(t *testing.T) {
	nonexistent := filepath.Join(os.TempDir(), "does-not-exist-ironrun.yml")
	cmd := exec.Command(cliBin, "--policy", nonexistent, "run", "anything")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for nonexistent policy file, got success")
	}
	// cobra sends errors to stderr
	combined := stderr.String()
	// Also capture stdout just in case
	if !strings.Contains(combined, "not found") {
		// Retry checking combined output from CombinedOutput
		out, _ := exec.Command(cliBin, "--policy", nonexistent, "run", "anything").CombinedOutput()
		if !strings.Contains(string(out), "not found") {
			t.Errorf("expected 'not found' in stderr/output, got stderr: %q  output: %q", combined, string(out))
		}
	}
}

func TestCLI_Validate_Valid(t *testing.T) {
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: build
    argv: [go, build, ./...]
    ttl: 5m
`)
	cmd := exec.Command(cliBin, "--policy", policy, "validate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("validate exited non-zero: %v\noutput: %s", err, out)
	}
	if !strings.Contains(string(out), "Policy valid") {
		t.Errorf("expected 'Policy valid' in validate output, got: %q", string(out))
	}
}

func TestCLI_Validate_Invalid(t *testing.T) {
	// Malformed YAML — missing required fields.
	policy := writeTempPolicyFile(t, `this: is: not: valid: yaml: at: all:::
  - bad
`)
	cmd := exec.Command(cliBin, "--policy", policy, "validate")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for invalid policy, got success\noutput: %s", out)
	}
}

func TestCLI_Run_ExitCodePassthrough(t *testing.T) {
	// `false` is a standard POSIX tool that always exits 1.
	falsePath, err := exec.LookPath("false")
	if err != nil {
		t.Skip("'false' binary not found in PATH, skipping")
	}
	policy := writeTempPolicyFile(t, fmt.Sprintf(`version: "1"
provider: passthrough
commands:
  - id: fail
    argv: [%s]
    ttl: 5s
`, falsePath))
	cmd := exec.Command(cliBin, "--policy", policy, "run", "fail")
	err = cmd.Run()
	code := exitCode(err)
	if code != 1 {
		t.Errorf("expected exit code 1 from ironrun run (passthrough of 'false'), got %d", code)
	}
}
