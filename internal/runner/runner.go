// Package runner executes a policy-authorized command in a child process,
// injects resolved secrets into the child's environment, streams stdout/stderr
// through a redacting writer, enforces timeout, and optionally blocks network.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	ErrCancelled            = errors.New("runner: command cancelled")
	ErrDenied               = errors.New("runner: command denied by policy")
	ErrCIUntrusted          = errors.New("runner: untrusted CI event — refusing to expose secrets")
	ErrNoNetworkUnsupported = errors.New("runner: no_network requested but network isolation cannot be enforced")
)

// waitDelayGrace bounds how long Wait blocks for pipe drain after the child
// exits or the context is done, so an orphaned grandchild holding a pipe can
// never wedge the run.
const waitDelayGrace = 3 * time.Second

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

	if err := CheckCITrust(opts.AllowPullRequestTarget); err != nil {
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

	// Apply TTL. The context is ALWAYS cancellable (even without a TTL) so a
	// lost output consumer (a broken stdout pipe from `… | head`) or a caller
	// signal can tear the run down and let cleanup run, rather than wedging Wait.
	runCtx := ctx
	var cancel context.CancelFunc
	if cmd.TTL.Duration > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cmd.TTL.Duration)
	} else {
		runCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

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

	// max_bytes is enforced by capWriter, DOWNSTREAM of redaction, so we can
	// report Truncated only when bytes were actually dropped (not merely when
	// output reached the cap exactly). The redactor's own cap is left unlimited.
	// cancelOnErr cancels the run if the live sink can no longer be written.
	maxBytes := cmd.MaxBytes
	stdoutCap := &capWriter{w: io.MultiWriter(&stdoutBuf, cancelOnErr{outDst, cancel}), max: maxBytes}
	stderrCap := &capWriter{w: io.MultiWriter(&stderrBuf, cancelOnErr{errDst, cancel}), max: maxBytes}
	stdoutW := redact.New(stdoutCap, secretValues, 0)
	stderrW := redact.New(stderrCap, secretValues, 0)

	// Build environment: inherit current env, then inject secrets.
	childEnv := buildEnv(opts.Env, opts.Secrets)

	// Construct the command.
	c := exec.CommandContext(runCtx, bin, cmd.Argv[1:]...)
	c.Env = childEnv
	c.Stdout = stdoutW
	c.Stderr = stderrW
	// A relative workdir is resolved against the project root (opts.WorkDir),
	// NOT ironrun's own process cwd — otherwise `ironrun -p /proj/ironrun.yml`
	// invoked from an unrelated directory would run the command there.
	switch {
	case cmd.WorkDir != "" && filepath.IsAbs(cmd.WorkDir):
		c.Dir = cmd.WorkDir
	case cmd.WorkDir != "" && opts.WorkDir != "":
		c.Dir = filepath.Join(opts.WorkDir, cmd.WorkDir)
	case cmd.WorkDir != "":
		c.Dir = cmd.WorkDir
	case opts.WorkDir != "":
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
	// shimArmed records whether the sealed-exec shim actually wrapped this run.
	// The post-run 124/125 correction below must only fire when it did, so a
	// target that legitimately exits 124/125 is not misreported as a shim refusal.
	shimArmed := false
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
		shimArmed = true
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

	// Run the child in its own process group so a TTL/cancel kill, and the
	// post-run sweep below, reach the WHOLE tree — not just the direct child.
	// A grandchild that calls setsid(2) detaches into its own session/group and
	// escapes this (accepted; it also loses the controlling terminal).
	setProcessGroup(c)
	// Kill the whole group when the context is done (timeout or cancellation),
	// not just the group leader, so secret-carrying grandchildren die too.
	c.Cancel = func() error {
		if c.Process != nil {
			killProcessGroup(c.Process.Pid)
		}
		// Returning ErrProcessDone-equivalent is wrong (the group may still be
		// alive); nil lets Wait surface the context error, which Run interprets.
		return nil
	}
	// Bound how long Wait blocks after the child exits or the context is done:
	// without this a grandchild still holding the stdout/stderr pipe would wedge
	// Wait indefinitely.
	c.WaitDelay = waitDelayGrace

	start := time.Now()
	runErr := c.Run()
	elapsed := time.Since(start)

	// Sweep the process group: SIGKILL anything the command left behind, so no
	// grandchild outlives the sealed run still holding injected secrets. Done
	// before cleanup so no survivor is still reading a file secret we remove.
	if c.Process != nil {
		killProcessGroup(c.Process.Pid)
	}

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
		case errors.Is(runCtx.Err(), context.Canceled):
			// Cancelled by the caller (a signal turned into cancellation) or by a
			// lost output consumer (`… | head`): the child was killed, so report
			// an error rather than a silent exit 0 / -1.
			retErr = ErrCancelled
		case cmd.EffectiveNoNetwork() && runtime.GOOS == "linux" && errors.Is(runErr, syscall.EPERM):
			// CLONE_NEWNET denied at exec time (unprivileged user namespaces
			// disabled): the child never started, so fail closed rather than
			// report a confusing generic exec error.
			retErr = fmt.Errorf("%w: network namespace creation was denied (unprivileged user namespaces unavailable)", ErrNoNetworkUnsupported)
			startFailed = true
		case errors.Is(runErr, exec.ErrWaitDelay):
			// The child itself exited but left a pipe open (an orphaned
			// grandchild still held it) and WaitDelay unblocked Wait. The command
			// ran, so report its real status; the group sweep above reaped the rest.
			exitCode = processStateExitCode(c.ProcessState)
		default:
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
				if exitCode < 0 {
					// Killed by a signal: report the POSIX 128+signo convention
					// instead of a bare -1 so the signal survives propagation.
					if code, ok := signalExitCode(exitErr.ProcessState); ok {
						exitCode = code
					}
				}
			} else {
				retErr = fmt.Errorf("runner: exec error: %w", runErr)
				startFailed = true
			}
		}
	}

	// Truncated is true only when bytes were actually dropped at the cap — not
	// when output merely reached the cap exactly.
	truncated := stdoutCap.dropped || stderrCap.dropped

	// Correct the pre-run seccomp status when the child never actually ran
	// with the filter: the shim's fail-closed refusals (exits 124/125) and a
	// failure to start the child at all both mean "installed" was never true
	// for an executed command. Only trust the 124/125 codes when the shim was
	// actually armed — otherwise a target that legitimately exits 124/125 would
	// be misreported as a shim refusal.
	switch {
	case startFailed:
		seccompInstalled, seccompDetail = false, "child process never started"
	case shimArmed && exitCode == sealedexec.ExitFilterRefused:
		seccompInstalled, seccompDetail = false, "shim refused: seccomp filter install failed (fail-closed); child never executed"
	case shimArmed && exitCode == sealedexec.ExitSealRefused:
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
	"DYLD_",    // all dyld_* loader controls (INSERT_LIBRARIES, *_PATH, …)
	// Shell startup hijack: shells execute these files/commands on startup.
	"BASH_ENV",
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
	"NODE_PATH",         // node module search-path hijack
	"RUBYOPT",           // ruby -r library injection
	"RUBYLIB",           // ruby load-path hijack
	"PERL5OPT",          // perl -M module injection
	"PERL5LIB",          // perl @INC hijack
	"JAVA_TOOL_OPTIONS", // JVM -javaagent/-agentpath native code
	"JDK_JAVA_OPTIONS",  // same, java launcher
	"_JAVA_OPTIONS",     // same, honored by the JVM
	"GOFLAGS",           // go: -toolexec runs an arbitrary binary on every build
	"GCONV_PATH",        // glibc iconv/gconv module loader hijack
	"RUSTC_WRAPPER",     // cargo/rustc: wrapper binary invoked per compile
	// Tool hijack: the child (or its grandchildren) may shell out to these.
	"GIT_SSH",     // GIT_SSH / GIT_SSH_COMMAND: command run in place of ssh
	"GIT_CONFIG_", // GIT_CONFIG_COUNT/KEY_n/VALUE_n/PARAMETERS: inline config → core.fsmonitor etc.
}

// dangerousEnvExact are stripped only on an exact match (prefix matching would
// catch unrelated, benign variables).
var dangerousEnvExact = map[string]bool{
	"ENV": true, // sh/ash startup file; must not match ENVIRONMENT etc.
}

// isDangerousEnv checks if an env var should be stripped for security.
func isDangerousEnv(key string) bool {
	if dangerousEnvExact[key] {
		return true
	}
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

// CheckCITrust fails closed on CI events where untrusted code could trigger
// secret exposure: GitHub fork PRs (pull_request, pull_request_review,
// pull_request_review_comment), workflow_run triggered from a fork, and
// pull_request_target, GitLab fork merge requests, CircleCI fork PR builds,
// and Jenkins change-request builds. Callers that resolve secrets must call it
// before resolution. allowPullRequestTarget is the operator-flag-only escape
// hatch for GitHub pull_request_target (the legacy IRONRUN_ALLOW_PRT=1 env
// form is ignored).
func CheckCITrust(allowPullRequestTarget bool) error {
	// GitHub Actions environment
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		event := os.Getenv("GITHUB_EVENT_NAME")
		switch event {
		case "pull_request", "pull_request_review", "pull_request_review_comment", "workflow_run":
			if err := checkGitHubEventRepos(event); err != nil {
				return err
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

// checkGitHubEventRepos reads the event payload at GITHUB_EVENT_PATH (GitHub
// sets no environment variable naming a PR's head repository) and fails
// closed unless the code under test comes from the base repository. A
// missing, unparsable or incomplete payload cannot prove that, so it is
// treated as untrusted.
func checkGitHubEventRepos(event string) error {
	type repo struct {
		FullName string `json:"full_name"`
	}
	var payload struct {
		PullRequest struct {
			Head struct {
				Repo repo `json:"repo"`
			} `json:"head"`
			Base struct {
				Repo repo `json:"repo"`
			} `json:"base"`
		} `json:"pull_request"`
		WorkflowRun struct {
			HeadRepository repo `json:"head_repository"`
		} `json:"workflow_run"`
		Repository repo `json:"repository"`
	}
	data, err := os.ReadFile(os.Getenv("GITHUB_EVENT_PATH"))
	if err == nil {
		err = json.Unmarshal(data, &payload)
	}
	if err != nil {
		return fmt.Errorf("%w: %s event payload unreadable, fork status unverifiable", ErrCIUntrusted, event)
	}
	head, base := payload.PullRequest.Head.Repo.FullName, payload.PullRequest.Base.Repo.FullName
	if event == "workflow_run" {
		head, base = payload.WorkflowRun.HeadRepository.FullName, payload.Repository.FullName
	}
	if head == "" || base == "" {
		return fmt.Errorf("%w: %s event payload names no head/base repository, fork status unverifiable", ErrCIUntrusted, event)
	}
	if !strings.EqualFold(head, base) {
		return fmt.Errorf("%w: %s event from fork %q", ErrCIUntrusted, event, head)
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

// sandboxExecPath is the macOS Seatbelt wrapper. It is an ABSOLUTE path, never
// resolved via PATH: PATH is agent-reachable, and a shadowed sandbox-exec would
// silently run the command with the network wide open. A package variable only
// so tests can point it at a missing path to exercise the fail-closed branch.
var sandboxExecPath = "/usr/bin/sandbox-exec"

func applyDarwinNetworkIsolation(c *exec.Cmd) error {
	// Fail closed if the system sandbox binary is absent.
	if _, err := os.Stat(sandboxExecPath); err != nil {
		return fmt.Errorf("%w: %s unavailable on this macOS host: %v", ErrNoNetworkUnsupported, sandboxExecPath, err)
	}
	// macOS sandbox-exec wraps the child with a Seatbelt profile:
	//   sandbox-exec -p <profile> <original-cmd...>
	// Allow everything the process normally does but deny all network. A blanket
	// (deny default) also blocks fork/sysctl/mach-lookup and breaks ordinary
	// build/test tooling (python, node, ruby, cargo, and any Go binary — which
	// cannot even read its page size), so we deny only the network.
	const profile = `(version 1)
(allow default)
(deny network*)
`
	c.Args = append([]string{"sandbox-exec", "-p", profile}, c.Args...)
	c.Path = sandboxExecPath
	return nil
}

// capWriter enforces a byte cap DOWNSTREAM of redaction and records whether it
// actually dropped anything, so the run can report Truncated precisely. max<=0
// means unlimited. A dropped write still reports len(p) consumed so the
// upstream redactor does not treat the cap as a short-write error.
type capWriter struct {
	w       io.Writer
	max     int64
	written int64
	dropped bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.max <= 0 {
		return c.w.Write(p)
	}
	remaining := c.max - c.written
	if remaining <= 0 {
		c.dropped = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		c.dropped = true
		n, err := c.w.Write(p[:remaining])
		c.written += int64(n)
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	n, err := c.w.Write(p)
	c.written += int64(n)
	return n, err
}

// cancelOnErr cancels the run when the live output sink can no longer be
// written — e.g. the consumer of ironrun's stdout closed the pipe (`… | head`).
// Without it a broken consumer would wedge Wait: our copy goroutine stops, the
// child blocks on a full pipe, and nothing ends the run (or runs cleanup).
type cancelOnErr struct {
	w      io.Writer
	cancel context.CancelFunc
}

func (c cancelOnErr) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if err != nil && c.cancel != nil {
		c.cancel()
	}
	return n, err
}

// processStateExitCode returns a process's exit code, mapping a signal death to
// the POSIX 128+signo convention instead of a bare -1.
func processStateExitCode(ps *os.ProcessState) int {
	if ps == nil {
		return -1
	}
	code := ps.ExitCode()
	if code < 0 {
		if c, ok := signalExitCode(ps); ok {
			return c
		}
	}
	return code
}
