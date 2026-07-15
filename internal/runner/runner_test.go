package runner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/runner"
)

func makeCmd(id, ttl string, argv ...string) *policy.Command {
	d := policy.Duration{}
	if ttl != "" {
		_ = d.SetDuration(ttl)
	}
	return &policy.Command{ID: id, Argv: argv, TTL: d}
}

func TestRun_Simple(t *testing.T) {
	cmd := makeCmd("echo", "", "echo", "hello")
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	if !strings.Contains(out.String(), "hello") {
		t.Errorf("expected 'hello' in output, got %q", out.String())
	}
}

func TestRun_NonzeroExit(t *testing.T) {
	cmd := makeCmd("false", "", "false")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("expected non-zero exit code")
	}
}

func TestRun_Timeout(t *testing.T) {
	cmd := makeCmd("sleep", "100ms", "sleep", "10")
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrTimeout) {
		t.Errorf("expected ErrTimeout, got %v", err)
	}
}

func TestRun_SecretNotInOutput(t *testing.T) {
	cmd := makeCmd("echo-secret", "", "sh")
	// shell is denied by policy
	_, err := runner.Run(context.Background(), cmd, runner.Options{})
	if !errors.Is(err, runner.ErrDenied) {
		t.Errorf("expected ErrDenied for shell, got %v", err)
	}
}

func TestRun_SecretsRedacted(t *testing.T) {
	// Use `echo` to try to print a "secret" value from the injected env.
	// The redactor should strip it from the captured output.
	secret := "ironrun-super-secret-value"
	cmd := makeCmd("printenv", "", "printenv", "IRONRUN_SECRET")
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &out,
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"IRONRUN_SECRET": secret},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	// Secret must not appear in stdout.
	if strings.Contains(out.String(), secret) {
		t.Errorf("secret leaked in stdout: %q", out.String())
	}
	// Redaction placeholder should appear.
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got %q", out.String())
	}
	// Result.Stdout also must not contain secret.
	if strings.Contains(res.Stdout, secret) {
		t.Errorf("secret leaked in Result.Stdout: %q", res.Stdout)
	}
}

func TestRun_RedactOnlyValueIsNotInjectedButIsFiltered(t *testing.T) {
	secret := "file-secret-content-never-visible"
	cmd := makeCmd("file-redaction", "", "printf", "%s", secret)
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out, Stderr: &bytes.Buffer{}, RedactValues: []string{secret}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) || strings.Contains(res.Stdout, secret) {
		t.Fatal("redaction-only file content leaked")
	}
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRun_CleanupRunsOnTimeoutBeforeAudit(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	cmd := makeCmd("timeout-cleanup", "20ms", "sleep", "2")
	_, err = runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Audit: logger,
		AuditSecrets: []audit.SecretUse{{Name: "credential", Kind: "file", Target: "CREDENTIAL_PATH"}},
		Cleanup:      func() error { return os.RemoveAll(dir) },
	})
	if !errors.Is(err, runner.ErrTimeout) {
		t.Fatalf("run error = %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("cleanup did not remove directory: %v", statErr)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var entry audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.CleanupResult != "removed" || len(entry.SecretUses) != 1 || entry.SecretUses[0].Kind != "file" {
		t.Fatalf("audit cleanup metadata = %#v", entry)
	}
}

func TestRun_EnvExfiltration(t *testing.T) {
	// Simulate `env` command — agent common exfil attempt.
	// Even if secret is in the child env, output should be redacted.
	secret := "do-not-expose-me"
	cmd := makeCmd("env", "", "env")
	var out bytes.Buffer
	_, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &out,
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"LEAKED_SECRET": secret},
	})
	if err != nil {
		t.Fatalf("env failed: %v", err)
	}
	if strings.Contains(out.String(), secret) {
		t.Errorf("env exfiltration succeeded — secret in output: %q", out.String())
	}
}

func TestRun_MaxBytes(t *testing.T) {
	// seq generates many lines of output and exits cleanly.
	cmd := makeCmd("seq", "30s", "seq", "1", "100000")
	cmd.MaxBytes = 100
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("seq failed: %v", err)
	}
	if out.Len() > 200 { // small margin for multi-byte placeholder overhead
		t.Errorf("output exceeded max_bytes: got %d bytes", out.Len())
	}
	if !res.Truncated {
		t.Error("expected Result.Truncated = true")
	}
}

func TestRun_DurationMs(t *testing.T) {
	cmd := makeCmd("sleep10ms", "1s", "sleep", "0.01")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.DurationMs < 5 {
		t.Errorf("expected duration ≥ 5ms, got %d", res.DurationMs)
	}
}

func TestRun_CIForkPRDenied(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_HEAD_REPOSITORY", "attacker/fork")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	cmd := makeCmd("echo", "", "echo", "hi")
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrCIUntrusted) {
		t.Errorf("expected ErrCIUntrusted for fork PR, got %v", err)
	}
}

func TestRun_CITrustedPR(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_HEAD_REPOSITORY", "owner/repo")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")

	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Errorf("expected trusted PR to succeed: %v", err)
	}
	if res != nil && res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
}

func TestRun_PullRequestTargetDeniedWithoutFlag(t *testing.T) {
	os.Unsetenv("IRONRUN_ALLOW_PRT")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")

	cmd := makeCmd("echo", "", "echo", "hi")
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrCIUntrusted) {
		t.Errorf("expected ErrCIUntrusted for pull_request_target, got %v", err)
	}
}

func TestRun_PullRequestTargetAllowedWithFlag(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	t.Setenv("IRONRUN_ALLOW_PRT", "1")

	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Errorf("expected success with IRONRUN_ALLOW_PRT=1: %v", err)
	}
	_ = res
}

func TestRun_WorkDir(t *testing.T) {
	cmd := makeCmd("pwd", "", "pwd")
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &out,
		Stderr:  &bytes.Buffer{},
		WorkDir: "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit 0, got %d", res.ExitCode)
	}
	if !strings.Contains(strings.TrimSpace(out.String()), "tmp") {
		t.Errorf("expected /tmp in pwd output, got %q", out.String())
	}
}

func TestRun_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cmd := makeCmd("sleep", "10s", "sleep", "10")
	_, err := runner.Run(ctx, cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Error("expected error when context cancelled")
	}
}
