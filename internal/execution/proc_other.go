//go:build !unix

package execution

// processAlive cannot be determined portably off Unix; assume alive so only the
// age fallback reclaims stale run directories.
func processAlive(pid int) bool { return true }
