//go:build !linux

package runner

import "os/exec"

// armSealedExec is a no-op on non-Linux platforms: the sealed-exec shim is
// Linux-only (seccomp + rlimit seal), so it can never be armed. Returning
// (false, nil) records that outcome via the seccomp status helper instead of
// failing the run.
func armSealedExec(c *exec.Cmd, noSeal, seccomp bool) (bool, error) { return false, nil }
