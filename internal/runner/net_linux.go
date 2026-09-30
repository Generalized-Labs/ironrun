//go:build linux

package runner

import (
	"os"
	"os/exec"
	"syscall"
)

func applyLinuxNetworkIsolation(c *exec.Cmd) error {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	// CLONE_NEWNET alone requires CAP_SYS_ADMIN in the current namespace, which
	// a non-root process does not have. Chaining CLONE_NEWUSER first creates an
	// unprivileged user namespace in which the process holds CAP_SYS_ADMIN, so
	// the subsequent network namespace creation is permitted. Both are denied
	// at exec time (EPERM) when unprivileged userns is disabled system-wide
	// (e.g. Ubuntu 24.04+ default AppArmor restriction); the runner detects
	// that and fails closed.
	c.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
	uid := os.Getuid()
	gid := os.Getgid()
	c.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: uid, Size: 1},
	}
	c.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: gid, Size: 1},
	}
	return nil
}
