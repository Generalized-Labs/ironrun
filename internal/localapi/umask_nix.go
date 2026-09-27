//go:build !windows

package localapi

import "syscall"

// narrowUmask narrows the process umask to 0077 around Unix socket creation
// so the socket is never visible with wider permissions, even briefly. It
// returns a restore function the caller must invoke immediately after the
// listen call.
func narrowUmask() (restore func()) {
	old := syscall.Umask(0077)
	return func() { syscall.Umask(old) }
}
