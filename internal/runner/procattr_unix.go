//go:build unix

package runner

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcessGroup makes the child the leader of a new process group so the
// whole tree can be signalled at once (see killProcessGroup). It preserves any
// SysProcAttr already set (e.g. the Linux network-namespace clone flags).
func setProcessGroup(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = &syscall.SysProcAttr{}
	}
	c.SysProcAttr.Setpgid = true
	setParentDeathSignal(c.SysProcAttr)
}

// killProcessGroup SIGKILLs the entire process group led by pid. A negative pid
// targets the group. Errors (notably ESRCH once the group is empty) are
// intentionally ignored — this is a best-effort sweep.
func killProcessGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// signalExitCode maps a signal-terminated child to the POSIX 128+signo code.
func signalExitCode(ps *os.ProcessState) (int, bool) {
	if ps == nil {
		return 0, false
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true
	}
	return 0, false
}
