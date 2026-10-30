//go:build windows

package vault

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockInitialization(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}
