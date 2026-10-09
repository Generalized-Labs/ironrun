package runner

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

// no_network must fail closed when the system sandbox binary is missing, rather
// than running the command with the network wide open. We force the missing
// path by pointing the (absolute) sandbox path at a nonexistent file — proving
// the resolution no longer depends on PATH.
func TestNoNetwork_FailsClosedWhenSandboxMissing(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific: exercises the sandbox-exec-missing path")
	}
	old := sandboxExecPath
	sandboxExecPath = filepath.Join(t.TempDir(), "does-not-exist-sandbox-exec")
	t.Cleanup(func() { sandboxExecPath = old })

	cmd := &policy.Command{ID: "echo", Argv: []string{"/bin/echo", "hi"}, NoNetwork: true}
	_, err := Run(context.Background(), cmd, Options{})
	if !errors.Is(err, ErrNoNetworkUnsupported) {
		t.Errorf("expected ErrNoNetworkUnsupported (fail-closed), got %v", err)
	}
}
