//go:build linux

package runner

import "syscall"

// setParentDeathSignal asks the kernel to SIGKILL the child if ironrun (its
// parent) dies, so a crashed ironrun cannot leave a secret-carrying child
// running. Best-effort backstop behind the explicit group teardown and the
// signal-to-cancel handling (the setting tracks the creating thread).
func setParentDeathSignal(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGKILL }
