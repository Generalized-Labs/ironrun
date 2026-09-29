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
	"github.com/generalized-labs/ironrun/internal/sealedexec"
)

// Result holds the outcome of a sealed command execution.
type Result struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	DurationMs      int64
	Truncated       bool // true if output was capped by max_bytes
	EntropyWarnings int  // count of high-entropy tokens flagged in (redacted) output
	// SeccompInstalled/Detail report this run's seccomp outcome (per-run, not
	// a process global, so concurrent runs cannot misattribute). Installed is
	// set optimistically when the sealed-exec shim is armed and corrected
	// post-run when the child never executed under the filter.
	SeccompInstalled bool
	SeccompDetail    string
}

// Options configures an execution.
type Options struct {
	Stdout  io.Writer         // where to stream stdout (default: os.Stdout)
	Stderr  io.Writer         // where to stream stderr (default: os.Stderr)
	Env     []string          // additional env vars for the child (KEY=VALUE)
	Secrets map[string]string // resolved secret values to inject
	// RedactValues are protected values that must be filtered from output but
	// are not themselves injected (for example, materialized file contents).
	RedactValues []string
	AuditSecrets []audit.SecretUse
	// Cleanup runs after the child exits (including timeout/cancellation) and
	// before the audit record is appended.
	Cleanup func() error
	WorkDir string

	// Seccomp, when non-nil and true, requests the Linux seccomp syscall filter.
	// Callers resolve it from policy (Command.SeccompEnabled); the legacy
	// IRONRUN_SECCOMP=off environment kill-switch is deliberately NOT honored
	// (see execution.resolveSeccomp). Leave nil for the seal-only shim (no
	// filter). Note the shim re-execs the calling binary (see armSealedExec):
	// unit tests that call Run directly exercise it through the test binary.
	Seccomp *bool
	// DisableEntropyScan skips the post-run high-entropy scan of (redacted)
	// output. This weakens a leak-detection control: it may only be set from an
	// explicit operator flag (e.g. `ironrun run --disable-entropy-scan`), never
	// from the environment, and its use is logged loudly to stderr.
	DisableEntropyScan bool
	// AllowPullRequestTarget permits secret exposure on GitHub
	// pull_request_target CI events. Operator flag only
	// (`--allow-pull-request-target`); the legacy IRONRUN_ALLOW_PRT=1
	// environment variable is ignored.
	AllowPullRequestTarget bool
	// NoSeal disables the sealed-child hardening (RLIMIT_CORE=0, anti-core-dump)
	// applied in the sealed-exec shim before execve of the target. Operator
	// flag only (`--no-seal`); any inherited IRONRUN_NO_SEAL environment value
	// is stripped and ignored. NOTE: the seal never blocked debugger attach —
	// PR_SET_DUMPABLE cannot survive execve (see sealedexec) — it exists to
	// keep secrets out of core dumps.
	NoSeal bool
	// Audit, when non-nil, receives one append-only entry per run. nil disables.
	Audit *audit.Logger
	// SessionID correlates audit entries from the same agent session / invocation.
	SessionID string
	// AllowShell is reserved for a human-approved trusted workspace session.
	// Strict policy commands always leave it false.
	AllowShell bool
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
	if !opts.AllowShell && policy.IsShellString(cmd.Argv) {
		return nil, fmt.Errorf("%w: shell commands are not allowed (argv[0]=%q)", ErrDenied, cmd.Argv[0])
	}

	if err := checkCITrust(opts.AllowPullRequestTarget); err != nil {
		return nil, err
	}
	// The legacy environment kill-switches are no longer honored: a contained
	// agent inherits the environment, so env-gated security controls are
	// agent-reachable. Warn loudly when they are set so operators learn the new
	// operator-flag-only mechanism instead of silently losing the control.
	for _, kv := range [][2]string{
		{"IRONRUN_ENTROPY_SCAN", "--disable-entropy-scan"},
		{"IRONRUN_ALLOW_PRT", "--allow-pull-request-target"},
	} {
		if os.Getenv(kv[0]) != "" {
			fmt.Fprintf(os.Stderr, "[ironrun] SECURITY WARNING: %s is set but no longer honored; use the %s operator flag instead\n", kv[0], kv[1])
		}
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
	for _, value := range opts.RedactValues {
		if len(value) >= minRedactableSecretLen {
			secretValues = append(secretValues, value)
			if len(value) >= minEncodableSecretLen {
				secretValues = append(secretValues, redact.Encodings(value, minEncodableSecretLen)...)
			}
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
	// Default-deny: secret-bearing commands get no network unless the policy
	// explicitly opts out (allow_network: true); see EffectiveNoNetwork.
	if cmd.EffectiveNoNetwork() {
		if err := applyNetworkIsolation(c); err != nil {
			return nil, err
		}
	}

	// Arm the sealed-exec shim (Linux). The child seal (RLIMIT_CORE=0,
	// anti-core-dump) is default-on for every run, INDEPENDENT of seccomp: the
	// shim is armed whenever the seal is enabled or seccomp was requested.
	// When seccomp was not requested the shim runs in seal-only mode
	// (IRONRUN_SKIP_SECCOMP=1). Must come after network isolation so it wraps
	// the final target. Everything here FAILS CLOSED: a hardening control that
	// silently never applies would be a downgrade the audit log cannot
	// distinguish from a real install.
	// seccompInstalled/seccompDetail are per-run locals, deliberately NOT a
	// process global: the audit entry and the returned Result both read them,
	// so concurrent runs (e.g. local API requests served by net/http) can
	// never misattribute another run's outcome to this one.
	seccompInstalled := false
	seccompDetail := "no run recorded yet"
	seccompRequested := opts.Seccomp != nil && *opts.Seccomp
	switch {
	case runtime.GOOS != "linux":
		// No shim off Linux (documented platform limitation).
		seccompInstalled, seccompDetail = false, "not installed: sealed-exec shim unsupported on GOOS="+runtime.GOOS
	case opts.NoSeal && !seccompRequested:
		// Nothing to harden: seal explicitly disabled and no filter requested.
		// (With seccomp requested the shim still arms for the filter.)
		seccompInstalled, seccompDetail = false, "not requested"
	default:
		if _, err := armSealedExec(c, opts.NoSeal, seccompRequested); err != nil {
			// The run itself fails closed at this point; the per-run seccomp
			// outcome is never reported, so no detail assignment is needed.
			return nil, err
		}
		if seccompRequested {
			seccompInstalled, seccompDetail = true, "shim armed; filter installs in-child before execve (fail-closed)"
		} else {
			seccompInstalled, seccompDetail = false, "seal-only shim (seccomp not requested; filter skipped)"
		}
	}

	if opts.NoSeal {
		// Loud on purpose: disabling the seal re-enables core dumps of the
		// secret-carrying child. Note it does NOT change debugger-attachability:
		// PR_SET_DUMPABLE cannot survive execve (see sealedexec), so the seal
		// never blocked debugger attach in the first place — it blocks core
		// dumps. Use --no-seal only for post-mortem core debugging.
		fmt.Fprintln(os.Stderr, "[ironrun] SECURITY WARNING: --no-seal: the secret-carrying child will NOT be sealed (RLIMIT_CORE=0 skipped — core dumps, which capture the child's secrets, are re-enabled)")
	}

	start := time.Now()
	runErr := c.Run()
	elapsed := time.Since(start)

	// Flush any buffered redaction.
	_ = stdoutW.Flush()
	_ = stderrW.Flush()
	cleanupResult := ""
	var cleanupErr error
	if opts.Cleanup != nil {
		if cleanupErr = opts.Cleanup(); cleanupErr != nil {
			cleanupResult = "failed"
		} else {
			cleanupResult = "removed"
		}
	}

	exitCode := 0
	var retErr error
	startFailed := false
	if runErr != nil {
		switch {
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			retErr = ErrTimeout
		case cmd.EffectiveNoNetwork() && runtime.GOOS == "linux" && errors.Is(runErr, syscall.EPERM):
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

	// Correct the pre-run seccomp status when the child never actually ran
	// with the filter: the shim's fail-closed refusals (exits 124/125) and a
	// failure to start the child at all both mean "installed" was never true
	// for an executed command.
	switch {
	case startFailed:
		seccompInstalled, seccompDetail = false, "child process never started"
	case exitCode == sealedexec.ExitFilterRefused:
		seccompInstalled, seccompDetail = false, "shim refused: seccomp filter install failed (fail-closed); child never executed"
	case exitCode == sealedexec.ExitSealRefused:
		seccompInstalled, seccompDetail = false, "shim refused: child seal failed (fail-closed); child never executed"
	}

	// Entropy warn pass (warn-only — never alters output). Runs on the already
	// redacted buffers, so it only flags tokens that survived redaction.
	// Operator-flag-only: the legacy IRONRUN_ENTROPY_SCAN=off environment
	// kill-switch is ignored (warned about above).
	entropyWarnings := 0
	if opts.DisableEntropyScan {
		fmt.Fprintln(os.Stderr, "[ironrun] SECURITY WARNING: --disable-entropy-scan: skipping the high-entropy output scan; unredacted secrets in output will not be flagged")
	} else {
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
			SecretUses:       opts.AuditSecrets,
			CleanupResult:    cleanupResult,
			RedactionCount:   int(stdoutW.RedactionCount() + stderrW.RedactionCount()),
			EntropyWarnings:  entropyWarnings,
			ExitCode:         exitCode,
			DurationMs:       elapsed.Milliseconds(),
			Truncated:        truncated,
			KillReason:       killReason,
			SeccompRequested: seccompRequested,
			SeccompInstalled: seccompInstalled,
			SeccompDetail:    seccompDetail,
			// secretValues already holds the exact values plus their encoded
			// variants (mirroring the redactor registration above); the audit
			// package scrubs all of them out of argv before writing.
			ScrubValues: secretValues,
			NoNetwork:   cmd.EffectiveNoNetwork(),
		}
		if err := opts.Audit.Append(entry); err != nil {
			fmt.Fprintf(os.Stderr, "[ironrun] warning: audit append failed: %v\n", err)
		}
	}

	if retErr != nil {
		return nil, retErr
	}
	if cleanupErr != nil {
		return nil, fmt.Errorf("runner: temporary secret cleanup failed: %w", cleanupErr)
	}

	return &Result{
		ExitCode:         exitCode,
		Stdout:           stdoutBuf.String(),
		Stderr:           stderrBuf.String(),
		DurationMs:       elapsed.Milliseconds(),
		Truncated:        truncated,
		EntropyWarnings:  entropyWarnings,
		SeccompInstalled: seccompInstalled,
		SeccompDetail:    seccompDetail,
	}, nil
}

// dangerousEnvPrefixes are environment variables that could be used to
// hijack child process execution or inject code. We strip these entirely from
// the inherited environment (policy-declared env entries are operator intent
// and are NOT stripped — only ambient inheritance is scrubbed).
var dangerousEnvPrefixes = []string{
	// Dynamic linker / loader injection (glibc, musl, dyld).
	"LD_PRELOAD",
	"LD_LIBRARY_PATH",
	"LD_AUDIT", // glibc audit modules: attacker .so loaded into every process
	"DYLD_INSERT_LIBRARIES",
	"DYLD_LIBRARY_PATH",
	// Shell startup hijack: shells execute these files/commands on startup.
	"BASH_ENV",
	"ENV",
	"ZDOTDIR", // zsh reads startup files from $ZDOTDIR
	"BASH_FUNC_",
	"SHELLOPTS",
	"BASHOPTS",
	"CDPATH",
	"GLOBIGNORE",
	"PROMPT_COMMAND",
	// Interpreter option/code injection: each of these makes the runtime load
	// attacker-influenced code or search paths.
	"PYTHON",            // PYTHONPATH/PYTHONHOME/PYTHONSTARTUP/PYTHONBREAKPOINT
	"NODE_OPTIONS",      // node --require / --import via env
	"RUBYOPT",           // ruby -r library injection
	"RUBYLIB",           // ruby load-path hijack
	"PERL5OPT",          // perl -M module injection
	"PERL5LIB",          // perl @INC hijack
	"JAVA_TOOL_OPTIONS", // JVM -javaagent/-agentpath native code
	"JDK_JAVA_OPTIONS",  // same, java launcher
	"_JAVA_OPTIONS",     // same, honored by the JVM
	// Tool hijack: the child (or its grandchildren) may shell out to these.
	"GIT_SSH", // GIT_SSH / GIT_SSH_COMMAND: command run in place of ssh
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

// checkCITrust fails closed on CI events where untrusted code could trigger
// secret exposure: GitHub fork PRs and pull_request_target, GitLab fork merge
// requests, CircleCI fork PR builds, and Jenkins change-request builds.
// allowPullRequestTarget is the operator-flag-only escape hatch for GitHub
// pull_request_target (the legacy IRONRUN_ALLOW_PRT=1 env form is ignored).
func checkCITrust(allowPullRequestTarget bool) error {
	// GitHub Actions environment
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
			// Require explicit operator opt-in via --allow-pull-request-target.
			if !allowPullRequestTarget {
				return fmt.Errorf("%w: pull_request_target requires --allow-pull-request-target", ErrCIUntrusted)
			}
			fmt.Fprintln(os.Stderr, "[ironrun] SECURITY WARNING: --allow-pull-request-target: exposing secrets to a pull_request_target CI run; the PR code is untrusted")
		}
	}

	// GitLab CI environment. A merge-request pipeline whose source project
	// differs from the MR's project is a fork MR: the code under test is
	// untrusted. When the project IDs are unavailable we cannot prove the MR
	// is same-project, so we fail closed.
	if os.Getenv("GITLAB_CI") == "true" {
		if os.Getenv("CI_PIPELINE_SOURCE") == "merge_request_event" {
			src := os.Getenv("CI_MERGE_REQUEST_SOURCE_PROJECT_ID")
			tgt := os.Getenv("CI_MERGE_REQUEST_PROJECT_ID")
			switch {
			case src != "" && tgt != "" && src != tgt:
				return fmt.Errorf("%w: GitLab fork merge request (source project %q != target project %q)", ErrCIUntrusted, src, tgt)
			case src == "" || tgt == "":
				return fmt.Errorf("%w: GitLab merge request pipeline with unverifiable fork status", ErrCIUntrusted)
			}
		}
	}

	// CircleCI environment. CIRCLE_PR_NUMBER / CIRCLE_PR_USERNAME /
	// CIRCLE_PR_REPONAME are only set for forked PR builds, so their presence
	// is the fork signal.
	if os.Getenv("CIRCLECI") == "true" {
		if pr := os.Getenv("CIRCLE_PR_NUMBER"); pr != "" {
			return fmt.Errorf("%w: CircleCI fork pull request build (CIRCLE_PR_NUMBER=%q)", ErrCIUntrusted, pr)
		}
		if user := os.Getenv("CIRCLE_PR_USERNAME"); user != "" {
			return fmt.Errorf("%w: CircleCI fork pull request build (CIRCLE_PR_USERNAME=%q)", ErrCIUntrusted, user)
		}
	}

	// Jenkins environment (multibranch / branch-source pipelines). CHANGE_ID
	// is only set for change-request builds. CHANGE_FORK identifies the source
	// fork when the branch-source plugin provides it; when it is absent we
	// cannot prove the change is same-repo, so we fail closed either way.
	if os.Getenv("JENKINS_URL") != "" || os.Getenv("JENKINS_HOME") != "" {
		if changeID := os.Getenv("CHANGE_ID"); changeID != "" {
			if fork := os.Getenv("CHANGE_FORK"); fork != "" {
				return fmt.Errorf("%w: Jenkins change build %q from fork %q", ErrCIUntrusted, changeID, fork)
			}
			return fmt.Errorf("%w: Jenkins change build %q with unverifiable fork status", ErrCIUntrusted, changeID)
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
