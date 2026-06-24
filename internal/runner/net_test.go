package runner_test

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/generalized-labs/ironrun/internal/runner"
)

// buildNetProbe compiles the testdata/netprobe fixture into a temp binary.
func buildNetProbe(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "netprobe")
	out, err := exec.Command("go", "build", "-o", bin, "./testdata/netprobe").CombinedOutput()
	if err != nil {
		t.Fatalf("build netprobe fixture: %v\n%s", err, out)
	}
	return bin
}

// TestNoNetwork_BlocksOutbound proves no_network actually blocks the network.
// Skips where isolation is unavailable (fail-closed ErrNoNetworkUnsupported) so
// it stays green on CI runners without unprivileged userns and on Windows.
func TestNoNetwork_BlocksOutbound(t *testing.T) {
	probe := buildNetProbe(t)
	cmd := makeCmd("netprobe", "20s", probe)
	cmd.NoNetwork = true

	var out, errb bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out, Stderr: &errb})
	if errors.Is(err, runner.ErrNoNetworkUnsupported) {
		t.Skipf("network isolation unavailable on this host (fail-closed): %v", err)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("network probe succeeded under no_network — isolation did NOT block it (stdout=%q stderr=%q)", out.String(), errb.String())
	}
}

// TestNoNetwork_FailsClosedWhenUnenforceable proves we refuse to run rather than
// run with the network open. On macOS we force the unenforceable path by hiding
// sandbox-exec (empty PATH); the command binary is given as an absolute path so
// it still resolves.
func TestNoNetwork_FailsClosedWhenUnenforceable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific: forces the sandbox-exec-missing path")
	}
	t.Setenv("PATH", "") // sandbox-exec will not resolve
	cmd := makeCmd("echo", "", "/bin/echo", "hi")
	cmd.NoNetwork = true
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrNoNetworkUnsupported) {
		t.Errorf("expected ErrNoNetworkUnsupported (fail-closed), got %v", err)
	}
}
