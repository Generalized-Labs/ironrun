package vault

import (
	"fmt"
	"os"
)

// withInitializationLock serializes protected-key creation across processes.
// The lock file is retained: unlinking it could let another caller lock a new
// inode while a waiter still holds the previous one. Closing the descriptor
// releases the kernel lock, including when a process crashes.
func withInitializationLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open vault initialization lock: %w", err)
	}
	defer f.Close()
	if err := lockInitialization(f); err != nil {
		return fmt.Errorf("acquire vault initialization lock: %w", err)
	}
	return fn()
}
