//go:build !windows

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock so concurrent appenders serialize
// their read-tail-then-append, keeping the hash chain consistent across processes.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
