//go:build !linux

package runner

import "os/exec"

// applySeccomp is a no-op on non-Linux platforms.
func applySeccomp(c *exec.Cmd) bool { return false }
