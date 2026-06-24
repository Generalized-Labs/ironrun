//go:build linux

package runner

import (
	"os/exec"
	"syscall"
)

func applyLinuxNetworkIsolation(c *exec.Cmd) error {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	// CLONE_NEWNET creates a new network namespace.
	// Requires unprivileged user namespaces (default on ubuntu-latest, Debian, Fedora).
	// The clone itself can still fail at exec time (EPERM) if userns is disabled;
	// the runner detects that and fails closed.
	c.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	return nil
}
