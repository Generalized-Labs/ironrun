//go:build !linux

package runner

import "os/exec"

func applyLinuxNetworkIsolation(c *exec.Cmd) error {
	// Unreachable: applyNetworkIsolation only dispatches here when GOOS == "linux".
	// Present so the symbol resolves on non-Linux builds.
	_ = c
	return nil
}
