//go:build unix && !linux

package runner

import "syscall"

// setParentDeathSignal is a no-op off Linux: PR_SET_PDEATHSIG has no portable
// equivalent (e.g. on macOS).
func setParentDeathSignal(a *syscall.SysProcAttr) {}
