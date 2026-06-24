//go:build linux

package sealedexec

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Classic BPF opcodes — these are the architecture-independent BPF virtual
// machine instruction set (a stable ABI), NOT syscall numbers, so they are safe
// to define directly. The arch-specific values (syscall numbers, AUDIT_ARCH_*)
// all come from x/sys/unix.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfJGE = 0x30
	bpfK   = 0x00
	bpfRET = 0x06
)

// seccomp_data field offsets: { __u32 nr; __u32 arch; ... }.
const (
	offNr   = 0
	offArch = 4
)

// x32SyscallBit marks an x32-ABI syscall number on amd64.
const x32SyscallBit = 0x40000000

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// deniedSyscalls are blocked in the sealed child. They are the syscalls used to
// read another process's memory or otherwise escalate; none are needed by
// ordinary build/test/deploy commands. Numbers come from x/sys/unix per-arch.
func deniedSyscalls() []uint32 {
	return []uint32{
		unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV,
		unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_KCMP,
		unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_BPF,
		unix.SYS_USERFAULTFD,
	}
}

func archInfo() (expected uint32, x32Guard bool, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, true, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, false, nil
	default:
		return 0, false, fmt.Errorf("seccomp unsupported on GOARCH=%s", runtime.GOARCH)
	}
}

// buildFilter assembles the denylist BPF program: validate the architecture,
// reject the x32 ABI on amd64, return EPERM for each denied syscall, allow the
// rest.
func buildFilter() ([]unix.SockFilter, error) {
	expected, x32Guard, err := archInfo()
	if err != nil {
		return nil, err
	}
	killProc := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	retErrno := uint32(unix.SECCOMP_RET_ERRNO) | (uint32(unix.EPERM) & uint32(unix.SECCOMP_RET_DATA))
	retAllow := uint32(unix.SECCOMP_RET_ALLOW)

	prog := []unix.SockFilter{
		// Load and validate seccomp_data.arch.
		stmt(bpfLD|bpfW|bpfABS, offArch),
		jump(bpfJMP|bpfJEQ|bpfK, expected, 1, 0), // == expected -> skip kill
		stmt(bpfRET|bpfK, killProc),
		// Load syscall number.
		stmt(bpfLD|bpfW|bpfABS, offNr),
	}
	if x32Guard {
		// nr >= 0x40000000 -> x32 ABI -> kill (defeats nr-based bypass).
		prog = append(prog,
			jump(bpfJMP|bpfJGE|bpfK, x32SyscallBit, 0, 1),
			stmt(bpfRET|bpfK, killProc),
		)
	}
	for _, nr := range deniedSyscalls() {
		// nr == denied -> fall through to RET ERRNO; else skip it.
		prog = append(prog,
			jump(bpfJMP|bpfJEQ|bpfK, nr, 0, 1),
			stmt(bpfRET|bpfK, retErrno),
		)
	}
	prog = append(prog, stmt(bpfRET|bpfK, retAllow))
	return prog, nil
}

// applySeccompFilter sets no_new_privs (required for unprivileged filter install)
// and loads the denylist filter. Called inside the sealed child just before execve.
func applySeccompFilter() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}
	prog, err := buildFilter()
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := syscall.RawSyscall(
		uintptr(unix.SYS_SECCOMP),
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		0,
		uintptr(unsafe.Pointer(&fprog)),
	)
	runtime.KeepAlive(prog)
	runtime.KeepAlive(&fprog)
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}
