package runner_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// setGitHubEvent mimics a real GitHub Actions run: the event name in the
// environment and the payload in the file GITHUB_EVENT_PATH points at.
func setGitHubEvent(t *testing.T, event, payload string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", event)
	t.Setenv("GITHUB_EVENT_PATH", path)
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
}

func prPayload(head, base string) string {
	return `{"pull_request":{"head":{"repo":{"full_name":"` + head + `"}},"base":{"repo":{"full_name":"` + base + `"}}}}`
}

func TestRun_CIForkPRDenied(t *testing.T) {
	setGitHubEvent(t, "pull_request", prPayload("attacker/fork", "owner/repo"))

	cmd := makeCmd("echo", "", "echo", "hi")
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrCIUntrusted) {
		t.Errorf("expected ErrCIUntrusted for fork PR, got %v", err)
	}
}

// REGRESSION: fork status used to come from GITHUB_HEAD_REPOSITORY, which
// GitHub never sets, so every real fork PR passed. It must come from the
// event payload, cover the review and workflow_run events, and fail closed
// when the payload cannot prove the code is same-repo.
func TestCheckCITrust_GitHubEventPayload(t *testing.T) {
	cases := []struct {
		name, event, payload string
		trusted              bool
	}{
		{"same-repo PR", "pull_request", prPayload("owner/repo", "owner/repo"), true},
		{"same repo, different case", "pull_request", prPayload("Owner/Repo", "owner/repo"), true},
		{"fork PR", "pull_request", prPayload("attacker/repo", "owner/repo"), false},
		{"fork PR review", "pull_request_review", prPayload("attacker/repo", "owner/repo"), false},
		{"fork PR review comment", "pull_request_review_comment", prPayload("attacker/repo", "owner/repo"), false},
		{"deleted fork (null head repo)", "pull_request", `{"pull_request":{"head":{"repo":null},"base":{"repo":{"full_name":"owner/repo"}}}}`, false},
		{"unparsable payload", "pull_request", `not json`, false},
		{"workflow_run from fork", "workflow_run", `{"workflow_run":{"head_repository":{"full_name":"attacker/repo"}},"repository":{"full_name":"owner/repo"}}`, false},
		{"workflow_run same repo", "workflow_run", `{"workflow_run":{"head_repository":{"full_name":"owner/repo"}},"repository":{"full_name":"owner/repo"}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setGitHubEvent(t, tc.event, tc.payload)
			err := runner.CheckCITrust(false)
			if tc.trusted && err != nil {
				t.Fatalf("expected trusted, got %v", err)
			}
			if !tc.trusted && !errors.Is(err, runner.ErrCIUntrusted) {
				t.Fatalf("expected ErrCIUntrusted, got %v", err)
			}
		})
	}
	t.Run("missing payload file", func(t *testing.T) {
		setGitHubEvent(t, "pull_request", prPayload("owner/repo", "owner/repo"))
		t.Setenv("GITHUB_EVENT_PATH", filepath.Join(t.TempDir(), "absent.json"))
		if err := runner.CheckCITrust(false); !errors.Is(err, runner.ErrCIUntrusted) {
			t.Fatalf("expected ErrCIUntrusted, got %v", err)
		}
	})
}

func TestRun_CITrustedPR(t *testing.T) {
	setGitHubEvent(t, "pull_request", prPayload("owner/repo", "owner/repo"))

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

	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		AllowPullRequestTarget: true, // operator flag, replaces IRONRUN_ALLOW_PRT=1
	})
	if err != nil {
		t.Errorf("expected success with AllowPullRequestTarget: %v", err)
	}
	_ = res
}

func TestRun_PullRequestTargetEnvKillSwitchIgnored(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	t.Setenv("IRONRUN_ALLOW_PRT", "1") // legacy env form: must be ignored

	cmd := makeCmd("echo", "", "echo", "hi")
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrCIUntrusted) {
		t.Errorf("expected IRONRUN_ALLOW_PRT=1 to be ignored, got %v", err)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written. Tests in this package never run in parallel, so this is safe.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestRun_EntropyScanEnvKillSwitchIgnored(t *testing.T) {
	t.Setenv("IRONRUN_ENTROPY_SCAN", "off") // legacy env form: must be ignored
	cmd := makeCmd("echo", "", "echo", "zQ3xV7bN2mK8pL4sT6wY9")
	var stderr string
	var res *runner.Result
	stderr = captureStderr(t, func() {
		var err error
		res, err = runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		if err != nil {
			t.Errorf("unexpected run error: %v", err)
		}
	})
	if res == nil || res.EntropyWarnings == 0 {
		t.Errorf("expected entropy scan to run despite IRONRUN_ENTROPY_SCAN=off, got %+v", res)
	}
	if !strings.Contains(stderr, "no longer honored") {
		t.Errorf("expected loud warning about the dead env var, got %q", stderr)
	}
}

func TestRun_DisableEntropyScanFlagWeakensLoudly(t *testing.T) {
	cmd := makeCmd("echo", "", "echo", "zQ3xV7bN2mK8pL4sT6wY9")
	var res *runner.Result
	stderr := captureStderr(t, func() {
		var err error
		res, err = runner.Run(context.Background(), cmd, runner.Options{
			Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, DisableEntropyScan: true,
		})
		if err != nil {
			t.Errorf("unexpected run error: %v", err)
		}
	})
	if res == nil || res.EntropyWarnings != 0 {
		t.Errorf("expected scan skipped with flag, got %+v", res)
	}
	if !strings.Contains(stderr, "SECURITY WARNING") || !strings.Contains(stderr, "--disable-entropy-scan") {
		t.Errorf("expected loud SECURITY WARNING for --disable-entropy-scan, got %q", stderr)
	}
}

func TestRun_NoSealFlagWarnsLoudly(t *testing.T) {
	cmd := makeCmd("echo", "", "echo", "hi")
	stderr := captureStderr(t, func() {
		_, err := runner.Run(context.Background(), cmd, runner.Options{
			Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, NoSeal: true,
		})
		if err != nil {
			t.Errorf("unexpected run error: %v", err)
		}
	})
	if !strings.Contains(stderr, "SECURITY WARNING") || !strings.Contains(stderr, "--no-seal") {
		t.Errorf("expected loud SECURITY WARNING for --no-seal, got %q", stderr)
	}
}

// SkipSeccompOutsideLinux gates the shim-specific tests: the sealed-exec shim
// and its sentinel handling are Linux-only by design (runner.go: no shim off
// Linux), so these expectations cannot hold on darwin/windows.
func SkipSeccompOutsideLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("sealed-exec shim expectations are Linux-specific; GOOS=%s has no shim", runtime.GOOS)
	}
}

func TestSeccompInstalled_AfterRunNotRequested(t *testing.T) {
	SkipSeccompOutsideLinux(t)
	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if res.SeccompInstalled {
		t.Errorf("expected installed=false when seccomp not requested (detail %q)", res.SeccompDetail)
	}
	if !strings.Contains(res.SeccompDetail, "not requested") {
		t.Errorf("expected detail to explain non-installation, got %q", res.SeccompDetail)
	}
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

// usernsNetAvailable reports whether this host can create unprivileged network
// namespaces — the mechanism behind no_network on Linux.
func usernsNetAvailable() bool {
	p, err := exec.LookPath("unshare")
	if err != nil {
		return false
	}
	c := exec.Command(p, "-Urn", "true")
	return c.Run() == nil
}

func TestRun_NoNetworkDefaultDenyForSecretBearingCommands(t *testing.T) {
	if runtime.GOOS != "linux" || !usernsNetAvailable() {
		t.Skip("requires Linux with unprivileged network namespaces")
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// Secret-bearing command, no explicit network setting: default deny.
	cmd := makeCmd("echo", "", "echo", "hi")
	cmd.Secrets = []string{"API_KEY"}
	if _, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Audit: logger,
		Secrets: map[string]string{"API_KEY": "supersecretvalue"},
	}); err != nil {
		t.Fatalf("secret-bearing run failed: %v", err)
	}
	// Secretless command: network stays open.
	cmd2 := makeCmd("echo2", "", "echo", "hi")
	if _, err := runner.Run(context.Background(), cmd2, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Audit: logger,
	}); err != nil {
		t.Fatalf("secretless run failed: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(lines))
	}
	var secretEntry, plainEntry audit.Entry
	if err := json.Unmarshal(lines[0], &secretEntry); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &plainEntry); err != nil {
		t.Fatal(err)
	}
	if !secretEntry.NoNetwork {
		t.Error("secret-bearing command without explicit network setting was not network-isolated (default deny)")
	}
	if plainEntry.NoNetwork {
		t.Error("secretless command should keep network access by default")
	}
}

func TestRun_NoNetworkExplicitOptOut(t *testing.T) {
	if runtime.GOOS != "linux" || !usernsNetAvailable() {
		t.Skip("requires Linux with unprivileged network namespaces")
	}
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	cmd := makeCmd("echo", "", "echo", "hi")
	cmd.Secrets = []string{"API_KEY"}
	cmd.AllowNetwork = true // explicit operator opt-out of the default deny
	if _, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Audit: logger,
		Secrets: map[string]string{"API_KEY": "supersecretvalue"},
	}); err != nil {
		t.Fatalf("run with allow_network failed: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var entry audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.NoNetwork {
		t.Error("allow_network: true should opt out of network isolation")
	}
}

func TestSeccompInstalled_SealOnlyShim(t *testing.T) {
	SkipSeccompOutsideLinux(t)
	// Seccomp not requested, seal on (default): the seal-only shim arms, but
	// the filter is skipped, so installed=false with a seal-only detail.
	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if res.SeccompInstalled {
		t.Errorf("expected installed=false in seal-only mode (detail %q)", res.SeccompDetail)
	}
	if !strings.Contains(res.SeccompDetail, "seal-only") {
		t.Errorf("expected seal-only detail, got %q", res.SeccompDetail)
	}
}

func TestSeccompInstalled_FilterRequested(t *testing.T) {
	SkipSeccompOutsideLinux(t)
	// Full hardening via the test binary's own re-exec: the shim installs the
	// real filter in-child and the run completes, so installed=true.
	seccomp := true
	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Seccomp: &seccomp,
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if !res.SeccompInstalled {
		t.Errorf("expected installed=true after a filtered run (detail %q)", res.SeccompDetail)
	}
}

func TestSeccompInstalled_NothingHardened(t *testing.T) {
	SkipSeccompOutsideLinux(t)
	// NoSeal + no seccomp: no shim at all.
	seccomp := false
	cmd := makeCmd("echo", "", "echo", "hi")
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Seccomp: &seccomp, NoSeal: true,
	})
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}
	if res.SeccompInstalled || res.SeccompDetail != "not requested" {
		t.Errorf("expected (false, \"not requested\"), got (%v, %q)", res.SeccompInstalled, res.SeccompDetail)
	}
}

func TestRun_ShimSentinelsStrippedFromTarget(t *testing.T) {
	SkipSeccompOutsideLinux(t)
	// End-to-end: the target's environment must not contain any shim sentinel,
	// whether the shim runs in full or seal-only mode.
	t.Setenv("IRONRUN_NO_SEAL", "1")      // must be stripped: env can't disable the seal
	t.Setenv("IRONRUN_SKIP_SECCOMP", "1") // must be stripped: env can't skip the filter
	t.Setenv("IRONRUN_SEALED_EXEC", "1")  // must be stripped: env can't fake the dispatch
	for _, seccomp := range []*bool{nil, boolPtr(true)} {
		var out bytes.Buffer
		cmd := makeCmd("env", "", "env")
		_, err := runner.Run(context.Background(), cmd, runner.Options{
			Stdout: &out, Stderr: &bytes.Buffer{}, Seccomp: seccomp,
		})
		if err != nil {
			t.Fatalf("env run failed (seccomp=%v): %v", seccomp, err)
		}
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(line, "IRONRUN_NO_SEAL=") ||
				strings.HasPrefix(line, "IRONRUN_SKIP_SECCOMP=") ||
				strings.HasPrefix(line, "IRONRUN_SEALED_EXEC=") {
				t.Errorf("shim sentinel leaked into target env (seccomp=%v): %q", seccomp, line)
			}
		}
	}
}

func boolPtr(b bool) *bool { return &b }

// TestRun_SeccompStatusPerRun: the seccomp outcome must be reported per-run
// on the Result, never via a process-global. Under concurrency (e.g. the
// local API serving parallel /v1/run requests) a last-write-wins global
// misattributes one run's seccomp_installed value to another run's audit
// record. Here two concurrent runs request different outcomes and each
// Result must carry its own.
func TestRun_SeccompStatusPerRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp install expectations are Linux-specific")
	}
	yes := true
	type outcome struct {
		res *runner.Result
		err error
	}
	withFilter := make(chan outcome, 1)
	sealOnly := make(chan outcome, 1)
	go func() {
		res, err := runner.Run(context.Background(), makeCmd("echo", "", "echo", "hi"), runner.Options{Stdout: io.Discard, Seccomp: &yes})
		withFilter <- outcome{res, err}
	}()
	go func() {
		res, err := runner.Run(context.Background(), makeCmd("echo", "", "echo", "hi"), runner.Options{Stdout: io.Discard})
		sealOnly <- outcome{res, err}
	}()
	a, b := <-withFilter, <-sealOnly
	if a.err != nil || b.err != nil {
		t.Fatalf("runs failed: %v %v", a.err, b.err)
	}
	if !a.res.SeccompInstalled || !strings.Contains(a.res.SeccompDetail, "shim armed") {
		t.Errorf("seccomp-requested run: got (%v, %q), want installed with %q", a.res.SeccompInstalled, a.res.SeccompDetail, "shim armed")
	}
	if b.res.SeccompInstalled {
		t.Errorf("seal-only run must report installed=false, got detail %q", b.res.SeccompDetail)
	}
}
