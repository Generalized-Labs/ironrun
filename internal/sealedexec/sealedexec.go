// Package sealedexec is the in-child shim the ironrun binary re-executes itself
// as in order to install a seccomp syscall filter before handing control to the
// real target binary.
//
// Go's os/exec gives no hook to run code between fork and execve, and cgo is
// disabled, so the parent re-execs the ironrun binary with a sentinel argv[0]
// and env var. main() detects that (via IsShim) and calls Run, which installs
// the filter and then execve's the target IN PLACE — the same PID — so the TTL
// kill (which targets the direct child) and the network namespace both still
// apply to the target.
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
// It installs the seccomp filter (best-effort: a failure is warned and the run
// continues, per the warn-first posture), strips the env sentinel so the target
// does not inherit it, and execve's the target. It never returns on success.
func Run(args []string) {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "[ironrun] sealed-exec: malformed invocation")
		os.Exit(126)
	}
	target := args[1]
	argv := args[2:]

	if err := applySeccompFilter(); err != nil {
		fmt.Fprintf(os.Stderr,
			"[ironrun] warning: seccomp filter not applied: %v; continuing without syscall hardening\n", err)
	}

	if err := syscall.Exec(target, argv, strippedEnv()); err != nil {
		fmt.Fprintf(os.Stderr, "[ironrun] sealed-exec: exec %q failed: %v\n", target, err)
		os.Exit(126)
	}
}

// strippedEnv returns the environment without the shim sentinel, so the target
// binary does not inherit it (which would also mis-trigger the shim if the
// target ever invokes ironrun recursively).
func strippedEnv() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	prefix := EnvSentinel + "="
	for _, e := range src {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
