package execution

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/runner"
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

// REGRESSION (2026-10 audit): GitHub reads workflow commands line by line, so
// printing a multi-line value after ::add-mask:: masked only its first line
// and wrote every later line to the job log in cleartext.
func TestEmitGitHubMasks_MultiLineValueNeverPrintedRaw(t *testing.T) {
	value := "TEST-FILE-SECRET-HEADER-0000\nTEST-FILE-SECRET-BODY-1111\nTEST-FILE-SECRET-FOOTER-2222\n"
	out := captureStdout(t, func() { emitGitHubMasks(nil, []string{value}) })
	masked := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !strings.HasPrefix(line, "::add-mask::") {
			t.Fatalf("non-command line reached the job log: %q", line)
		}
		masked[strings.TrimPrefix(line, "::add-mask::")] = true
	}
	for _, want := range []string{"TEST-FILE-SECRET-HEADER-0000", "TEST-FILE-SECRET-BODY-1111", "TEST-FILE-SECRET-FOOTER-2222"} {
		if !masked[want] {
			t.Errorf("line %q has no mask of its own", want)
		}
	}
}

// REGRESSION: the CI trust gate used to run inside runner.Run, after the
// provider had resolved every secret and after the masks were printed. An
// untrusted event must be refused before either happens.
func TestRun_UntrustedCIRefusedBeforeResolution(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	t.Setenv("IRONRUN_TEST_CI_GATE", "TEST-SECRET-0000")
	f, err := policy.Parse([]byte(`version: "1"
provider: env
commands:
  - id: gated
    argv: [printenv, TOKEN]
    allow_network: true
    env:
      TOKEN: env:IRONRUN_TEST_CI_GATE
`))
	if err != nil {
		t.Fatal(err)
	}
	var runErr error
	out := captureStdout(t, func() {
		_, runErr = Run(context.Background(), f, "ironrun.yml", t.TempDir(), "gated", Options{
			Stdout: io.Discard, Stderr: io.Discard, EmitGitHubMasks: true,
		})
	})
	if !errors.Is(runErr, runner.ErrCIUntrusted) {
		t.Fatalf("expected ErrCIUntrusted, got %v", runErr)
	}
	if out != "" {
		t.Fatalf("resolved secrets reached stdout before the CI gate: %q", out)
	}
}
