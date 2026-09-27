//go:build linux

package runner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/generalized-labs/ironrun/internal/sealedexec"
)

// armSealedExec rewrites c to re-exec the ironrun binary as the sealed-exec
// shim, which applies the child seal (RLIMIT_CORE=0, anti-core-dump) and —
// unless seccomp is false — installs the seccomp filter, then execve's the
// real target in place. It returns (true, nil) when the rewrite was applied.
//
// The shim is armed whenever the seal is enabled (the default) OR seccomp was
// requested: the seal is default-on for every run, independent of seccomp, and
// os/exec offers no pre-exec hook, so the re-exec is the only way to apply
// the rlimit to the child. When seccomp is false the shim gets
// IRONRUN_SKIP_SECCOMP=1 and installs no filter (seal-only mode).
//
// noSeal carries the operator's --no-seal flag to the shim. Any inherited
// IRONRUN_NO_SEAL or IRONRUN_SKIP_SECCOMP value is stripped first: the seal
// may only be disabled — and the filter may only be skipped — by explicit
// operator choice, never by ambient environment an agent could control.
//
// This requires the calling binary to be the ironrun binary, whose main()
// dispatches the shim via sealedexec.IsShim. Callers invoking runner.Run from a
// different binary (e.g. a unit-test binary) must NOT arm the shim — exercise
// it through the built ironrun binary instead.
//
// Fail-closed: failing to arm the shim is an error and aborts the run — a
// requested hardening control that silently never applies would be a downgrade
// the audit log cannot distinguish from a real install.
func armSealedExec(c *exec.Cmd, noSeal, seccomp bool) (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("runner: sealed-exec shim requested but cannot locate own executable: %w", err)
	}
	target := c.Path
	c.Args = append([]string{sealedexec.Sentinel, target}, c.Args...)
	c.Path = self
	env := make([]string, 0, len(c.Env)+3)
	for _, e := range c.Env {
		if strings.HasPrefix(e, sealedexec.EnvNoSeal+"=") ||
			strings.HasPrefix(e, sealedexec.EnvSkipSeccomp+"=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, sealedexec.EnvSentinel+"=1")
	if noSeal {
		env = append(env, sealedexec.EnvNoSeal+"=1")
	}
	if !seccomp {
		env = append(env, sealedexec.EnvSkipSeccomp+"=1")
	}
	c.Env = env
	return true, nil
}
