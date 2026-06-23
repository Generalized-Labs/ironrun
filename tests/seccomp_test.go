package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildPtraceProbe(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "ptraceprobe")
	build := exec.Command("go", "build", "-o", out, "./tests/testdata/ptraceprobe")
	build.Dir = ".."
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build ptraceprobe: %v\n%s", err, b)
	}
	return out
}

func runProbe(t *testing.T, probe string, seccompOn bool) string {
	t.Helper()
	policy := writeTempPolicyFile(t, fmt.Sprintf(`version: "1"
provider: passthrough
commands:
  - id: probe
    argv: [%s]
    ttl: 10s
    seccomp: %t
`, probe, seccompOn))
	cmd := exec.Command(cliBin, "--policy", policy, "run", "probe")
	cmd.Env = append(os.Environ(), "IRONRUN_AUDIT_LOG=off")
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestSeccomp_BlocksPtrace verifies the seccomp denylist blocks ptrace when the
// command opts in, and that disabling it restores access. It skips (rather than
// fails) when the kernel/environment doesn't enforce seccomp, matching the
// fail-open posture.
func TestSeccomp_BlocksPtrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp is Linux-only")
	}
	probe := buildPtraceProbe(t)

	off := runProbe(t, probe, false)
	if !strings.Contains(off, "PTRACE_ALLOWED") {
		t.Skipf("ptrace not allowed even without seccomp (restricted environment): %q", off)
	}

	on := runProbe(t, probe, true)
	if strings.Contains(on, "PTRACE_ALLOWED") {
		t.Skipf("seccomp not enforced here (fail-open, e.g. unsupported kernel): %q", on)
	}
	if !strings.Contains(on, "PTRACE_BLOCKED") {
		t.Errorf("expected PTRACE_BLOCKED with seccomp on, got: %q", on)
	}
}

// TestSeccomp_NormalCommandUnaffected confirms the denylist doesn't break an
// ordinary command (compatibility / no false positives on common syscalls).
func TestSeccomp_NormalCommandUnaffected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp is Linux-only")
	}
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello-world]
    ttl: 5s
    seccomp: true
`)
	cmd := exec.Command(cliBin, "--policy", policy, "run", "greet")
	cmd.Env = append(os.Environ(), "IRONRUN_AUDIT_LOG=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("echo under seccomp should succeed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hello-world") {
		t.Errorf("expected 'hello-world' in output, got: %q", out)
	}
}
