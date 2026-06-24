//go:build windows

package audit

import "os"

// Windows has no flock; rely on O_APPEND (atomic for the small single-line
// writes we make) plus the in-process mutex. Cross-process concurrency is
// best-effort on Windows.
func lockFile(f *os.File) error   { return nil }
func unlockFile(f *os.File) error { return nil }
