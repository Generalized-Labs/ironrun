//go:build linux

package runner

import (
	"os/exec"
	"syscall"
)

func applyLinuxNetworkIsolation(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	// CLONE_NEWNET creates a new network namespace.
	// Requires unprivileged user namespaces (default on ubuntu-latest, Debian, Fedora).
	c.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET
}
