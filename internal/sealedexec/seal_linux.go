//go:build linux

package sealedexec

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sealChild hardens the secret-carrying child just before execve of the target:
//
//   - RLIMIT_CORE={0,0}: no core file, ever. Core dumps contain the full
//     address space — secrets included — and persist on disk where they can
//     be mined post-compromise. rlimits live in the signal_struct, so this
//     SURVIVES execve into the target (the same mechanism as `ulimit -c 0`).
//
// What sealChild deliberately does NOT do: PR_SET_DUMPABLE=0. Verified
// 2026-09-27: the dumpable flag lives in the mm_struct, and execve replaces
// the mm — a PR_SET_DUMPABLE=0 issued in the shim reads back 0 in the shim
// but 1 in the execve'd target (proven with minimal C and Go reproducers).
// A pre-exec prctl therefore cannot make an arbitrary target binary
// non-dumpable; keeping it would be security theater. See the package doc for
// the full analysis, the residual risks (same-UID debugger attach and
// /proc/<pid>/environ reads remain possible), and the follow-ups that would
// close them (LD_PRELOAD seal library, fd-based secret delivery).
func sealChild() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_CORE, 0): %w", err)
	}
	return nil
}
