// Package tests contains integration and exfiltration tests.
// These tests verify that secrets cannot escape ironrun's sealed execution
// boundary via common exfiltration vectors.
package tests

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/runner"
)

// exfilSecret is the canary value. If it appears anywhere in captured
// output, the test fails — the secret has exfiltrated.
const exfilSecret = "ironrun-canary-xK9mQ2pR"

// runWithSecret executes the given argv with the canary injected as
// IRONRUN_CANARY and returns captured stdout+stderr.
func runWithSecret(t *testing.T, argv ...string) (stdout, stderr string, exitCode int, err error) {
	t.Helper()
	d := policy.Duration{}
	_ = d.SetDuration("10s")
	cmd := &policy.Command{
		ID:   "test",
		Argv: argv,
		TTL:  d,
	}
	var outBuf, errBuf bytes.Buffer
	res, runErr := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &outBuf,
		Stderr:  &errBuf,
		Secrets: map[string]string{"IRONRUN_CANARY": exfilSecret},
	})
	if runErr != nil {
		return "", "", -1, runErr
	}
	return outBuf.String(), errBuf.String(), res.ExitCode, nil
}

// assertNoLeak fails the test if the canary appears anywhere in s.
func assertNoLeak(t *testing.T, label, s string) {
	t.Helper()
	if strings.Contains(s, exfilSecret) {
		t.Errorf("EXFILTRATION via %s — canary found in output:\n%s", label, s)
	}
}

// --- Exfiltration test matrix ---

// 1. printenv / env — classic "dump all env vars" exfil.
func TestExfil_Printenv(t *testing.T) {
	out, errOut, _, err := runWithSecret(t, "printenv")
	if err != nil {
		t.Skip("printenv not available:", err)
	}
	assertNoLeak(t, "printenv stdout", out)
	assertNoLeak(t, "printenv stderr", errOut)
}

func TestExfil_Env(t *testing.T) {
	out, errOut, _, err := runWithSecret(t, "env")
	if err != nil {
		t.Skip("env not available:", err)
	}
	assertNoLeak(t, "env stdout", out)
	assertNoLeak(t, "env stderr", errOut)
}

// 2. echo $ENVVAR — direct echo of injected secret.
func TestExfil_EchoDirect(t *testing.T) {
	// We inject the secret as an env var. Use a script that echoes it.
	// Note: argv-exact matching means we can't use shell expansion directly
	// — but we test what happens when the *binary itself* emits it.
	out, errOut, _, err := runWithSecret(t, "printenv", "IRONRUN_CANARY")
	if err != nil {
		t.Skip("printenv not available:", err)
	}
	assertNoLeak(t, "printenv IRONRUN_CANARY stdout", out)
	assertNoLeak(t, "printenv IRONRUN_CANARY stderr", errOut)
}

// 3. cat /proc/self/environ (Linux) — reads own process env from procfs.
func TestExfil_ProcSelfEnviron(t *testing.T) {
	if _, err := os.Stat("/proc/self/environ"); os.IsNotExist(err) {
		t.Skip("not Linux, skipping /proc/self/environ test")
	}
	out, errOut, _, err := runWithSecret(t, "cat", "/proc/self/environ")
	if err != nil {
		t.Skip("cat not available:", err)
	}
	assertNoLeak(t, "/proc/self/environ stdout", out)
	assertNoLeak(t, "/proc/self/environ stderr", errOut)
}

// 4. Large output — verify redaction holds across chunk boundaries.
func TestExfil_LargeOutput_SecretAtBoundary(t *testing.T) {
	// Write a file containing: padding + secret + more padding
	// Then cat it. The secret will arrive at an arbitrary chunk boundary.
	tmpFile, err := os.CreateTemp("", "ironrun-exfil-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	padding := strings.Repeat("A", 4096)
	content := padding + exfilSecret + padding
	tmpFile.WriteString(content)
	tmpFile.Close()

	out, errOut, _, runErr := runWithSecret(t, "cat", tmpFile.Name())
	if runErr != nil {
		t.Skip("cat not available:", runErr)
	}
	assertNoLeak(t, "large output stdout", out)
	assertNoLeak(t, "large output stderr", errOut)
}

// 5. Secret appearing in Result.Stdout (captured string, not just live stream).
func TestExfil_ResultStruct(t *testing.T) {
	d := policy.Duration{}
	_ = d.SetDuration("10s")
	cmd := &policy.Command{
		ID:   "printenv",
		Argv: []string{"printenv", "IRONRUN_CANARY"},
		TTL:  d,
	}
	var outBuf bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &outBuf,
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"IRONRUN_CANARY": exfilSecret},
	})
	if err != nil {
		t.Skip("printenv not available:", err)
	}
	// The secret must not appear in the Result struct either.
	if strings.Contains(res.Stdout, exfilSecret) {
		t.Errorf("EXFILTRATION in Result.Stdout: %q", res.Stdout)
	}
	if strings.Contains(res.Stderr, exfilSecret) {
		t.Errorf("EXFILTRATION in Result.Stderr: %q", res.Stderr)
	}
}

// 6. Multiple secrets simultaneously.
func TestExfil_MultipleSecrets(t *testing.T) {
	secrets := map[string]string{
		"SECRET_A": "ironrun-secret-alpha-7x",
		"SECRET_B": "ironrun-secret-beta-9y",
		"SECRET_C": "ironrun-secret-gamma-3z",
	}
	d := policy.Duration{}
	_ = d.SetDuration("10s")
	cmd := &policy.Command{ID: "env", Argv: []string{"env"}, TTL: d}
	var outBuf, errBuf bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &outBuf,
		Stderr:  &errBuf,
		Secrets: secrets,
	})
	if err != nil {
		t.Skip("env not available:", err)
	}
	for k, v := range secrets {
		if strings.Contains(outBuf.String(), v) {
			t.Errorf("secret %s leaked in live stdout", k)
		}
		if strings.Contains(res.Stdout, v) {
			t.Errorf("secret %s leaked in Result.Stdout", k)
		}
	}
}

// 7. Shell command denied — ironrun must not allow sh/bash in argv.
func TestExfil_ShellDenied(t *testing.T) {
	d := policy.Duration{}
	_ = d.SetDuration("5s")
	cmd := &policy.Command{
		ID:   "shell",
		Argv: []string{"sh", "-c", "echo $IRONRUN_CANARY"},
		TTL:  d,
	}
	_, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"IRONRUN_CANARY": exfilSecret},
	})
	if err == nil {
		t.Error("expected shell command to be denied")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected 'denied' in error, got: %v", err)
	}
}

// 8. Empty secret list — output passthrough works correctly.
func TestNoSecrets_OutputPassthrough(t *testing.T) {
	d := policy.Duration{}
	_ = d.SetDuration("5s")
	cmd := &policy.Command{ID: "echo", Argv: []string{"echo", "plaintext-output"}, TTL: d}
	var outBuf bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &outBuf,
		Stderr:  &bytes.Buffer{},
		Secrets: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	if !strings.Contains(outBuf.String(), "plaintext-output") {
		t.Errorf("expected 'plaintext-output' in stdout, got %q", outBuf.String())
	}
}
