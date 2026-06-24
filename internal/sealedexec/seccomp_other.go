//go:build !linux

package sealedexec

// applySeccompFilter is a no-op on non-Linux platforms: seccomp is Linux-only.
func applySeccompFilter() error { return nil }
