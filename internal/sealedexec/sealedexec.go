// Package sealedexec is the in-child shim the ironrun binary re-executes itself
// as in order to harden the secret-carrying child before handing control to
// the real target binary.
//
// Go's os/exec gives no hook to run code between fork and execve, and cgo is
// disabled, so the parent re-execs the ironrun binary with a sentinel argv[0]
// and env var. main() detects that (via IsShim) and calls Run, which applies
// the child seal and (unless skipped) installs the seccomp filter, then
// execve's the target IN PLACE — the same PID — so the TTL kill (which targets
// the direct child) and the network namespace both still apply to the target.
//
// What the seal is (and is not):
//
//   - RLIMIT_CORE=0 on the child: core dumps contain the full address space,
//     secrets included. rlimits live in the signal_struct, so they SURVIVE
//     execve into the target — verified by strace (prlimit64(RLIMIT_CORE,
//     {0,0}) pre-execve) and by the long-standing `ulimit -c 0` semantics.
//   - The seccomp denylist (when not skipped): blocks the child's ptrace(2),
//     process_vm_readv/writev, perf_event_open, bpf, and userfaultfd syscalls.
//     Seccomp filters are attached to the task and SURVIVE execve — verified:
//     ptrace(PTRACE_TRACEME) in a shim-launched target returns EPERM while the
//     same binary run directly succeeds. NOTE the direction: this stops a
//     compromised CHILD from tracing the host, not a host debugger from
//     tracing the child.
//
// Deliberately NOT part of the seal: PR_SET_DUMPABLE=0. Verified 2026-09-27
// (kernel 7.0.0-38-generic): the dumpable flag lives in the mm_struct, and
// execve replaces the mm — so a PR_SET_DUMPABLE=0 set in the shim is reset to
// 1 by the very execve that starts the target (proven with minimal C and Go
// reproducers: flag reads 0 in the shim, 1 in the target). Keeping the prctl
// would be security theater: it cannot make an arbitrary target binary
// non-dumpable. Consequences, stated plainly:
//
//   - A same-UID debugger CAN still attach to the target (ptrace_may_access
//     consults the target's own dumpable flag), and /proc/<pid>/environ
//     remains owner-readable. The seal does not close those paths.
//   - What the seal DOES guarantee: no core dumps of the child, ever; and the
//     child cannot use ptrace/userfaultfd/perf against the host.
//
// The honest follow-up to close the debugger-attach path is an LD_PRELOAD seal
// library (constructor runs post-execve in the target's own mm) or fd-based
// secret delivery so secrets never sit in environ at all (already on the
// roadmap as deferred). Until then, hosts that need it should set the Yama
// ptrace_scope sysctl.
package sealedexec

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

const (
	// Sentinel is argv[0] when the ironrun binary is re-executed as the shim.
	Sentinel = "ironrun-sealed-exec"
	// EnvSentinel guards the dispatch in addition to the argv[0] sentinel.
	EnvSentinel = "IRONRUN_SEALED_EXEC"
	// EnvNoSeal, when set to "1" in the shim's environment, disables the
	// anti-coredump child seal. It is set by the parent ONLY when the human
	// operator passed --no-seal; any inherited value is stripped by the
	// parent before the shim is armed, and the shim strips it again before
	// execve so the target never sees it.
	EnvNoSeal = "IRONRUN_NO_SEAL"
	// EnvSkipSeccomp, when set to "1" in the shim's environment, skips the
	// seccomp filter install while still applying the child seal. The parent
	// sets it when the seal is armed but the operator/policy did not request
	// seccomp (or explicitly disabled it). Like EnvNoSeal, any inherited
	// value is stripped by the parent; the shim strips it before execve.
	EnvSkipSeccomp = "IRONRUN_SKIP_SECCOMP"
)

// Exit codes for shim failures, exported so the runner can interpret a
// refused child in its post-run seccomp-status bookkeeping.
// 124/125 = the child must not start (fail-closed); 126 = malformed
// invocation or exec failure (matches the historic codes).
const (
	ExitSealRefused   = 124
	ExitFilterRefused = 125
	exitBroken        = 126
)

var (
	// installFilter and installSeal are variables (not direct calls) so tests
	// can inject failures and verify the fail-closed behavior.
	installFilter = applySeccompFilter
	installSeal   = sealChild
)

// IsShim reports whether this process was launched as the sealed-exec shim.
// Both the argv[0] sentinel and the env sentinel must be present.
func IsShim(args []string) bool {
	return len(args) > 0 && args[0] == Sentinel && os.Getenv(EnvSentinel) == "1"
}

// init dispatches the shim as early as possible — before any main() or test
// main runs. This is what makes the re-exec safe even when the running binary is
// not the ironrun CLI (e.g. a `go test` binary that transitively imports this
// package via the runner): without it, such a binary would re-run its own main
// on re-exec and recurse. Any binary that can request seccomp imports this
// package, so the dispatch always fires.
func init() {
	if IsShim(os.Args) {
		Run(os.Args)
	}
}

// Run is the shim entry point. It expects:
//
//	args[0]  = Sentinel
//	args[1]  = absolute path of the target binary
//	args[2:] = the target's argv (argv[0]..argv[n])
//
// It installs the seccomp filter unless IRONRUN_SKIP_SECCOMP=1 (FAIL-CLOSED: a
// failure aborts the run via exit 125 rather than continuing unhardened),
// applies the anti-coredump child seal unless --no-seal was passed (FAIL-CLOSED
// via exit 124), strips the shim sentinels so the target does not inherit
// them, and execve's the target. It never returns on success.
func Run(args []string) {
	os.Exit(run(args))
}

// run contains the shim logic and returns the process exit code, so tests can
// exercise the fail-closed paths without exiting the test binary.
func run(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "[ironrun] sealed-exec: malformed invocation")
		return exitBroken
	}
	target := args[1]
	argv := args[2:]

	if os.Getenv(EnvSkipSeccomp) != "1" {
		if err := installFilter(); err != nil {
			fmt.Fprintf(os.Stderr,
				"[ironrun] sealed-exec: FATAL: seccomp filter install failed (%v); refusing to run the child unhardened (fail-closed)\n", err)
			return ExitFilterRefused
		}
	}

	if os.Getenv(EnvNoSeal) == "1" {
		fmt.Fprintln(os.Stderr,
			"[ironrun] sealed-exec: WARNING: child seal disabled by operator --no-seal: core dumps are re-enabled for this child")
	} else if err := installSeal(); err != nil {
		fmt.Fprintf(os.Stderr,
			"[ironrun] sealed-exec: FATAL: child seal failed (%v); refusing to run an unsealed secret-carrying child (fail-closed)\n", err)
		return ExitSealRefused
	}

	if err := syscall.Exec(target, argv, strippedEnv()); err != nil {
		fmt.Fprintf(os.Stderr, "[ironrun] sealed-exec: exec %q failed: %v\n", target, err)
		return exitBroken
	}
	return 0 // unreachable
}

// strippedEnv returns the environment without the shim sentinels, so the target
// binary does not inherit them (which would also mis-trigger the shim if the
// target ever invokes ironrun recursively).
func strippedEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, e := range src {
		if strings.HasPrefix(e, EnvSentinel+"=") ||
			strings.HasPrefix(e, EnvNoSeal+"=") ||
			strings.HasPrefix(e, EnvSkipSeccomp+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}
