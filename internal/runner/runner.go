// Package runner executes a policy-authorized command in a child process,
// injects resolved secrets into the child's environment, streams stdout/stderr
// through a redacting writer, enforces timeout, and optionally blocks network.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/redact"
)

// Result holds the outcome of a sealed command execution.
type Result struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMs int64
	Truncated  bool // true if output was capped by max_bytes
	// RedactionCount is the number of secret values redacted from output — the
	// per-run trust signal surfaced to the operator and the agent.
	RedactionCount int
}

// Options configures an execution.
type Options struct {
	Stdout  io.Writer         // where to stream stdout (default: os.Stdout)
	Stderr  io.Writer         // where to stream stderr (default: os.Stderr)
	Env     []string          // additional env vars for the child (KEY=VALUE)
	Secrets map[string]string // resolved secret values to inject
	WorkDir string
}

var (
	ErrTimeout     = errors.New("runner: command timed out")
	ErrDenied      = errors.New("runner: command denied by policy")
	ErrCIUntrusted = errors.New("runner: untrusted CI event — refusing to expose secrets")
)

// Run executes cmd according to policy, injecting secrets, enforcing TTL,
// and streaming redacted output to opts.Stdout / opts.Stderr.
func Run(ctx context.Context, cmd *policy.Command, opts Options) (*Result, error) {
	if len(cmd.Argv) == 0 {
		return nil, fmt.Errorf("%w: empty argv", ErrDenied)
	}

	// Deny shell execution from policy itself.
	if policy.IsShellString(cmd.Argv) {
		return nil, fmt.Errorf("%w: shell commands are not allowed (argv[0]=%q)", ErrDenied, cmd.Argv[0])
	}

	if err := checkCITrust(); err != nil {
		return nil, err
	}

	// Resolve binary path.
	bin, err := exec.LookPath(cmd.Argv[0])
	if err != nil {
		return nil, fmt.Errorf("runner: binary %q not found: %w", cmd.Argv[0], err)
	}

	// Build secrets slice for redactor (values only). An empty resolved value
	// cannot be redacted (it would match nothing), so warn — this usually means
	// a misconfigured provider reference, and the variable will be injected
	// without redaction coverage.
	// Values shorter than this are not treated as redactable: a 1-3 byte
	// "secret" matches so much ordinary output that redacting it corrupts the
	// stream (and can mask real leaks) while protecting nothing real. Real
	// credentials are never this short, so warn and skip rather than redact.
	const minRedactableSecretLen = 4
	secretValues := make([]string, 0, len(opts.Secrets))
	for name, v := range opts.Secrets {
		if v == "" {
			fmt.Fprintf(os.Stderr, "[ironrun] warning: secret %q resolved to an empty value — it cannot be redacted\n", name)
			continue
		}
		if len(v) < minRedactableSecretLen {
			fmt.Fprintf(os.Stderr, "[ironrun] warning: secret %q resolved to a very short value (<%d bytes) — skipping redaction to avoid corrupting output; check the provider reference\n", name, minRedactableSecretLen)
			continue
		}
		// Register the literal value plus its common encodings (base64/hex/URL)
		// so a command that emits an encoded form of the secret is still caught.
		secretValues = append(secretValues, SecretVariants(v)...)
	}

	// Set up output writers.
	var stdoutBuf, stderrBuf strings.Builder
	outDst := opts.Stdout
	if outDst == nil {
		outDst = os.Stdout
	}
	errDst := opts.Stderr
	if errDst == nil {
		errDst = os.Stderr
	}

	maxBytes := cmd.MaxBytes
	stdoutW := redact.New(io.MultiWriter(outDst, &stdoutBuf), secretValues, maxBytes)
	stderrW := redact.New(io.MultiWriter(errDst, &stderrBuf), secretValues, maxBytes)

	// Apply TTL.
	runCtx := ctx
	var cancel context.CancelFunc
	if cmd.TTL.Duration > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cmd.TTL.Duration)
		defer cancel()
	}

	// Build environment: inherit current env, then inject secrets.
	childEnv := buildEnv(opts.Env, opts.Secrets)

	// Construct the command.
	c := exec.CommandContext(runCtx, bin, cmd.Argv[1:]...)
	c.Env = childEnv
	c.Stdout = stdoutW
	c.Stderr = stderrW
	if cmd.WorkDir != "" {
		c.Dir = cmd.WorkDir
	} else if opts.WorkDir != "" {
		c.Dir = opts.WorkDir
	}

	// Apply network isolation (best-effort, platform-specific).
	if cmd.NoNetwork {
		applyNetworkIsolation(c)
	}

	start := time.Now()
	runErr := c.Run()
	elapsed := time.Since(start)

	// Flush any buffered redaction.
	stdoutW.Flush()
	stderrW.Flush()

	exitCode := 0
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("runner: exec error: %w", runErr)
		}
	}

	return &Result{
		ExitCode:       exitCode,
		Stdout:         stdoutBuf.String(),
		Stderr:         stderrBuf.String(),
		DurationMs:     elapsed.Milliseconds(),
		Truncated:      maxBytes > 0 && (stdoutW.BytesWritten() >= maxBytes || stderrW.BytesWritten() >= maxBytes),
		RedactionCount: int(stdoutW.Redactions() + stderrW.Redactions()),
	}, nil
}

// dangerousEnvPrefixes are environment variables that could be used to
// hijack child process execution or inject code. We strip these entirely.
var dangerousEnvPrefixes = []string{
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	"BASH_ENV",
	"ENV",
	"BASH_FUNC_",
	"SHELLOPTS",
	"BASHOPTS",
	"CDPATH",
	"GLOBIGNORE",
	"PROMPT_COMMAND",
}

// isDangerousEnv checks if an env var should be stripped for security.
func isDangerousEnv(key string) bool {
	for _, prefix := range dangerousEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// buildEnv constructs the child process environment.
// Base: current process env (with dangerous vars stripped).
// Then: any opts.Env overrides.
// Then: injected secrets (KEY=VALUE).
func buildEnv(extra []string, secrets map[string]string) []string {
	var env []string
	for _, e := range os.Environ() {
		key := strings.SplitN(e, "=", 2)[0]
		if !isDangerousEnv(key) {
			env = append(env, e)
		}
	}
	env = append(env, extra...)
	for k, v := range secrets {
		env = append(env, k+"="+v)
	}
	return env
}

// checkCITrust fails closed on fork PRs and pull_request_target events
// where untrusted code could trigger secret exposure.
func checkCITrust() error {
	// GITHUB_ACTIONS environment
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		event := os.Getenv("GITHUB_EVENT_NAME")
		if event == "pull_request" {
			// Check for fork PR.
			headRepo := os.Getenv("GITHUB_HEAD_REPOSITORY")
			baseRepo := os.Getenv("GITHUB_REPOSITORY")
			if headRepo != "" && headRepo != baseRepo {
				return fmt.Errorf("%w: fork pull_request event from %q", ErrCIUntrusted, headRepo)
			}
		}
		if event == "pull_request_target" {
			// pull_request_target always gets secrets but runs in context of untrusted code.
			// Require explicit opt-in via IRONRUN_ALLOW_PRT=1.
			if os.Getenv("IRONRUN_ALLOW_PRT") != "1" {
				return fmt.Errorf("%w: pull_request_target requires IRONRUN_ALLOW_PRT=1", ErrCIUntrusted)
			}
		}
	}
	return nil
}

// applyNetworkIsolation configures the Cmd to run with network access blocked.
// On Linux: uses a new network namespace (requires no special privileges on
// most modern kernels with user namespaces enabled).
// On macOS: uses sandbox-exec with a deny-all network profile.
// On other platforms: logs a warning and skips (best-effort).
func applyNetworkIsolation(c *exec.Cmd) {
	switch runtime.GOOS {
	case "linux":
		applyLinuxNetworkIsolation(c)
	case "darwin":
		applyDarwinNetworkIsolation(c)
	}
}

func applyDarwinNetworkIsolation(c *exec.Cmd) {
	// macOS sandbox-exec wraps the child with a Seatbelt profile.
	// We re-wrap the command: sandbox-exec -p <profile> <original-cmd...>
	const profile = `(version 1)
(deny default)
(allow process-exec)
(allow file-read*)
(allow file-write*)
(deny network*)
`
	origBin := c.Path
	origArgs := c.Args // includes argv[0]
	newArgs := append([]string{"sandbox-exec", "-p", profile}, origArgs...)
	c.Path = "/usr/bin/sandbox-exec"
	c.Args = newArgs
	_ = origBin // kept for clarity
}
