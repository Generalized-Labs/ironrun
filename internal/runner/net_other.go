//go:build !linux

package runner

import "os/exec"

func applyLinuxNetworkIsolation(c *exec.Cmd) {
	// No-op on non-Linux platforms.
}
