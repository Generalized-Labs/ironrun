//go:build !unix

package runner

import (
	"os"
	"os/exec"
)

// Process-group control is Unix-only; these are no-ops elsewhere.
func setProcessGroup(c *exec.Cmd)                    {}
func killProcessGroup(pid int)                       {}
func signalExitCode(ps *os.ProcessState) (int, bool) { return 0, false }
