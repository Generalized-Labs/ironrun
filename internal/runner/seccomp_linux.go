//go:build linux

package runner

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/generalized-labs/ironrun/internal/sealedexec"
)

// applySeccomp rewrites c to re-exec the ironrun binary as the sealed-exec shim,
// which installs a seccomp filter and then execve's the real target in place.
// Returns true if the rewrite was applied (seccomp requested).
//
// This requires the calling binary to be the ironrun binary, whose main()
// dispatches the shim via sealedexec.IsShim. Callers invoking runner.Run from a
// different binary (e.g. a unit-test binary) must NOT enable seccomp — exercise
// it through the built ironrun binary instead.
func applySeccomp(c *exec.Cmd) bool {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ironrun] warning: seccomp not applied (cannot locate self): %v\n", err)
		return false
	}
	target := c.Path
	c.Args = append([]string{sealedexec.Sentinel, target}, c.Args...)
	c.Path = self
	c.Env = append(c.Env, sealedexec.EnvSentinel+"=1")
	return true
}
