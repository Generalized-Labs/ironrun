package execution

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns what
// was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestEmitGitHubMasks_NotGatedOnEnv(t *testing.T) {
	// REGRESSION: mask emission must never be gated on the GITHUB_ACTIONS
	// environment variable — the environment is agent-reachable, so an
	// env-gated switch let a contained agent dump every secret to stdout.
	// Only Options.EmitGitHubMasks (the --emit-github-masks operator flag,
	// checked at the Run call site) triggers emission.
	const value = "super-secret-value-12345"

	outWith := captureStdout(t, func() {
		emitGitHubMasks(map[string]string{"A": value}, nil)
	})
	t.Setenv("GITHUB_ACTIONS", "")
	outWithout := captureStdout(t, func() {
		emitGitHubMasks(map[string]string{"A": value}, nil)
	})
	if outWith != outWithout {
		t.Errorf("emission must not depend on GITHUB_ACTIONS env: with=%q without=%q", outWith, outWithout)
	}
	if !strings.Contains(outWith, "::add-mask::"+value+"\n") {
		t.Errorf("expected value mask, got: %q", outWith)
	}
}

func TestEmitGitHubMasks_EmitsValueAndVariants(t *testing.T) {
	const value = "super-secret-value-12345"
	out := captureStdout(t, func() {
		emitGitHubMasks(map[string]string{"A": value}, []string{"another-secret-file-content-67890"})
	})
	if !strings.Contains(out, "::add-mask::"+value+"\n") {
		t.Errorf("expected exact value mask, got: %q", out)
	}
	// A base64 variant must also be masked.
	if !strings.Contains(out, "::add-mask::") {
		t.Errorf("expected variant masks, got: %q", out)
	}
	if !strings.Contains(out, "::add-mask::another-secret-file-content-67890\n") {
		t.Errorf("expected extra (file-secret) value mask, got: %q", out)
	}
}

func TestEmitGitHubMasks_SkipsShortValues(t *testing.T) {

	out := captureStdout(t, func() {
		emitGitHubMasks(map[string]string{"A": "tiny"}, nil)
	})
	if strings.Contains(out, "::add-mask::tiny") {
		t.Errorf("short values must be skipped, got: %q", out)
	}
}

func TestEmitGitHubMasks_Dedupes(t *testing.T) {

	const value = "super-secret-value-12345"
	out := captureStdout(t, func() {
		emitGitHubMasks(map[string]string{"A": value, "B": value}, []string{value})
	})
	if n := strings.Count(out, "::add-mask::"+value+"\n"); n != 1 {
		t.Errorf("expected value masked exactly once, got %d in: %q", n, out)
	}
}
