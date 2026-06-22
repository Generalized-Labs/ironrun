package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runDoctor runs `ironrun doctor` in dir and returns output and the exit code.
func runDoctor(t *testing.T, dir string) (string, int) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, "doctor")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running doctor: %v\noutput: %s", err, out)
	}
	return string(out), code
}

func writePolicy(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ironrun.yml"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

// TestDoctor_AllPass: a valid env-provider policy whose binary resolves passes
// every check and exits 0.
func TestDoctor_AllPass(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: ver
    argv: [go, version]
`)
	out, code := runDoctor(t, dir)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	for _, want := range []string{"valid", "redaction self-test passed", "All checks passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\noutput:\n%s", want, out)
		}
	}
}

// TestDoctor_MissingBinary: a command whose binary is absent fails with a
// non-zero exit and a clear message.
func TestDoctor_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: nope
    argv: [definitely-not-a-real-binary-xyz]
`)
	out, code := runDoctor(t, dir)
	if code == 0 {
		t.Fatalf("expected non-zero exit for missing binary\noutput:\n%s", out)
	}
	if !strings.Contains(out, "not found on PATH") {
		t.Errorf("expected 'not found on PATH'\noutput:\n%s", out)
	}
}

// TestDoctor_NoPolicy: with no policy file, doctor fails and points at init.
func TestDoctor_NoPolicy(t *testing.T) {
	dir := t.TempDir()
	out, code := runDoctor(t, dir)
	if code == 0 {
		t.Fatalf("expected non-zero exit when policy is missing\noutput:\n%s", out)
	}
	if !strings.Contains(out, "ironrun init") {
		t.Errorf("expected init hint in output\noutput:\n%s", out)
	}
}

// TestDoctor_ShellCommandWarned: a shell-string command is flagged (denied at
// runtime) rather than passed.
func TestDoctor_ShellCommandWarned(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `version: "1"
provider: env
commands:
  - id: sh
    argv: [sh, -c, "echo hi"]
`)
	out, _ := runDoctor(t, dir)
	if !strings.Contains(out, "shell invocation") {
		t.Errorf("expected shell command to be flagged\noutput:\n%s", out)
	}
}
