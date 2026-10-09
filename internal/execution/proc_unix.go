//go:build unix

package execution

import (
	"errors"
	"syscall"
)

// processAlive reports whether a process with the given PID currently exists.
// Signal 0 performs error checking without delivering a signal: ESRCH means the
// process is gone; EPERM means it exists but is owned by another user (treated
// as alive). PID reuse can make a dead owner look alive, which only delays
// cleanup to the age fallback — it never deletes a live run.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
