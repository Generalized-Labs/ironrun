package runner_test

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	// A DISTINCT marker proves the dial was actively blocked, not that the probe
	// crashed before dialing (the old assertion — exit != 0 — could not tell the
	// two apart).
	if !strings.Contains(out.String(), "DIAL_BLOCKED") {
		t.Errorf("no_network did not block the dial (exit=%d stdout=%q stderr=%q)", res.ExitCode, out.String(), errb.String())
	}
	if res.ExitCode == 0 {
		t.Errorf("network probe exited 0 under no_network (stdout=%q)", out.String())
	}
}

// TestNoNetwork_AllowsFork proves the macOS sandbox profile lets a sandboxed
// command fork/exec a child — the old (deny default) profile broke this for
// python/node/ruby/cargo and every Go binary.
func TestNoNetwork_AllowsFork(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific sandbox profile behavior")
	}
	bin := buildProcfix(t)
	cmd := makeCmd("fork", "", bin, "fork-exec")
	cmd.NoNetwork = true
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(out.String(), "child-ok") {
		t.Errorf("sandboxed command could not fork a child: exit=%d out=%q", res.ExitCode, out.String())
	}
}
