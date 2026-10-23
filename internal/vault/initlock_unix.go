//go:build !windows

package vault

import (
	"os"
	"syscall"
)

func lockInitialization(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}
