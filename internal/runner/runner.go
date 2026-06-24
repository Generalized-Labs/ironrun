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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/redact"
)

// Result holds the outcome of a sealed command execution.
type Result struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	DurationMs      int64
	Truncated       bool // true if output was capped by max_bytes
	EntropyWarnings int  // count of high-entropy tokens flagged in (redacted) output
}

// Options configures an execution.
type Options struct {
	Stdout  io.Writer         // where to stream stdout (default: os.Stdout)
	Stderr  io.Writer         // where to stream stderr (default: os.Stderr)
	Env     []string          // additional env vars for the child (KEY=VALUE)
	Secrets map[string]string // resolved secret values to inject
	WorkDir string

	// Seccomp, when non-nil and true, requests the Linux seccomp syscall filter.
	// Callers resolve it from policy (Command.SeccompEnabled) and the
	// IRONRUN_SECCOMP env kill-switch. Leave nil to skip (e.g. unit tests that
	// call Run directly — see applySeccomp's note on the re-exec requirement).
	Seccomp *bool
	// Audit, when non-nil, receives one append-only entry per run. nil disables.
	Audit *audit.Logger
	// SessionID correlates audit entries from the same agent session / invocation.
	SessionID string
}

var (
	ErrTimeout              = errors.New("runner: command timed out")
	ErrDenied               = errors.New("runner: command denied by policy")
	ErrCIUntrusted          = errors.New("runner: untrusted CI event — refusing to expose secrets")
	ErrNoNetworkUnsupported = errors.New("runner: no_network requested but network isolation cannot be enforced")
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
	// Only derive encoded variants (base64/hex/url) for secrets at least this
	// long, so the derivations stay specific enough not to over-redact ordinary
	// output.
	const minEncodableSecretLen = 8
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
		secretValues = append(secretValues, v)
		// Also redact common encodings (base64/hex/url) of the value so a process
		// that transforms a secret before printing it can't bypass redaction.
		if len(v) >= minEncodableSecretLen {
			secretValues = append(secretValues, redact.Encodings(v, minEncodableSecretLen)...)
		}
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

	// Apply network isolation. This is a security control, so it FAILS CLOSED:
	// if isolation cannot be enforced (unsupported platform, missing sandbox-exec),
	// we refuse to run rather than execute with the network wide open.
	if cmd.NoNetwork {
		if err := applyNetworkIsolation(c); err != nil {
			return nil, err
		}
	}

	// Apply seccomp syscall filtering (Linux; best-effort, fails open). Must come
	// after network isolation so it wraps the final target.
	seccompRequested := false
	if opts.Seccomp != nil && *opts.Seccomp {
		seccompRequested = applySeccomp(c)
	}

	start := time.Now()
	runErr := c.Run()
	elapsed := time.Since(start)

	// Flush any buffered redaction.
	stdoutW.Flush()
	stderrW.Flush()

	exitCode := 0
	var retErr error
	startFailed := false
	if runErr != nil {
		switch {
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			retErr = ErrTimeout
		case cmd.NoNetwork && runtime.GOOS == "linux" && errors.Is(runErr, syscall.EPERM):
			// CLONE_NEWNET denied at exec time (unprivileged user namespaces
			// disabled): the child never started, so fail closed rather than
			// report a confusing generic exec error.
			retErr = fmt.Errorf("%w: network namespace creation was denied (unprivileged user namespaces unavailable)", ErrNoNetworkUnsupported)
			startFailed = true
		default:
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				retErr = fmt.Errorf("runner: exec error: %w", runErr)
				startFailed = true
			}
		}
	}

	truncated := maxBytes > 0 && (stdoutW.BytesWritten() >= maxBytes || stderrW.BytesWritten() >= maxBytes)

	// Entropy warn pass (warn-only — never alters output). Runs on the already
	// redacted buffers, so it only flags tokens that survived redaction.
	entropyWarnings := 0
	if os.Getenv("IRONRUN_ENTROPY_SCAN") != "off" {
		hits := redact.ScanHighEntropy(stdoutBuf.String())
		hits = append(hits, redact.ScanHighEntropy(stderrBuf.String())...)
		entropyWarnings = len(hits)
		if entropyWarnings > 0 {
			fmt.Fprintf(os.Stderr, "[ironrun] warning: %d high-entropy token(s) in output may be an unredacted secret (first at offset %d, ~%.1f bits/char); if any is a secret, add it to your policy so it gets redacted\n", entropyWarnings, hits[0].Offset, hits[0].Entropy)
		}
	}

	// Record an audit entry (best-effort; never fails the run). Skip when the
	// process never started — there is nothing meaningful to record.
	if opts.Audit != nil && !startFailed {
		killReason := ""
		switch {
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			killReason = "timeout"
		case errors.Is(runCtx.Err(), context.Canceled):
			killReason = "cancelled"
		}
		names := make([]string, 0, len(opts.Secrets))
		for k := range opts.Secrets {
			names = append(names, k)
		}
		sort.Strings(names)
		cwd, _ := os.Getwd()
		entry := audit.Entry{
			Timestamp:        time.Now().UTC(),
			SessionID:        opts.SessionID,
			Cwd:              cwd,
			CommandID:        cmd.ID,
			Argv:             cmd.Argv,
			SecretNames:      names,
			RedactionCount:   int(stdoutW.RedactionCount() + stderrW.RedactionCount()),
			EntropyWarnings:  entropyWarnings,
			ExitCode:         exitCode,
			DurationMs:       elapsed.Milliseconds(),
			Truncated:        truncated,
			KillReason:       killReason,
			SeccompRequested: seccompRequested,
			NoNetwork:        cmd.NoNetwork,
		}
		if err := opts.Audit.Append(entry); err != nil {
			fmt.Fprintf(os.Stderr, "[ironrun] warning: audit append failed: %v\n", err)
		}
	}

	if retErr != nil {
		return nil, retErr
	}

	return &Result{
		ExitCode:        exitCode,
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		DurationMs:      elapsed.Milliseconds(),
		Truncated:       truncated,
		EntropyWarnings: entropyWarnings,
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
// On Linux: a new network namespace (CLONE_NEWNET; needs unprivileged userns).
// On macOS: sandbox-exec with a deny-all network profile.
// On any other platform — or when the platform mechanism is unavailable — it
// returns ErrNoNetworkUnsupported so the caller can FAIL CLOSED.
func applyNetworkIsolation(c *exec.Cmd) error {
	switch runtime.GOOS {
	case "linux":
		return applyLinuxNetworkIsolation(c)
	case "darwin":
		return applyDarwinNetworkIsolation(c)
	default:
		return fmt.Errorf("%w: no implementation for GOOS=%s", ErrNoNetworkUnsupported, runtime.GOOS)
	}
}

func applyDarwinNetworkIsolation(c *exec.Cmd) error {
	// macOS sandbox-exec wraps the child with a Seatbelt profile:
	//   sandbox-exec -p <profile> <original-cmd...>
	sandboxBin, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return fmt.Errorf("%w: sandbox-exec not found on this macOS host", ErrNoNetworkUnsupported)
	}
	const profile = `(version 1)
(deny default)
(allow process-exec)
(allow file-read*)
(allow file-write*)
(deny network*)
`
	c.Args = append([]string{"sandbox-exec", "-p", profile}, c.Args...)
	c.Path = sandboxBin
	return nil
}
