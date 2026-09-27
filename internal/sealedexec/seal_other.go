//go:build !linux

package sealedexec

// sealChild is a no-op on non-Linux platforms: the RLIMIT_CORE seal is
// Linux-only here, and the seccomp filter does not exist off Linux.
// Secret-carrying children on non-Linux platforms do not get the
// anti-coredump seal — a documented platform limitation.
func sealChild() error { return nil }
