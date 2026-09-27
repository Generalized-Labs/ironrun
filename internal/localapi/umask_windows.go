//go:build windows

package localapi

// narrowUmask is a no-op on Windows: syscall.Umask does not exist there and
// the local API's Unix socket path is unsupported on Windows anyway (the
// server refuses to start).
func narrowUmask() (restore func()) {
	return func() {}
}
