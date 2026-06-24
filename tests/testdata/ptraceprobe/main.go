//go:build linux

// Command ptraceprobe reports whether PTRACE_TRACEME is permitted in the current
// process. ironrun's seccomp filter blocks ptrace, so under it this call returns
// EPERM. It is built and run only by the Linux-gated seccomp integration test.
package main

import (
	"fmt"
	"syscall"
)

func main() {
	const ptraceTraceMe = 0
	_, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, ptraceTraceMe, 0, 0)
	switch errno {
	case 0:
		fmt.Println("PTRACE_ALLOWED")
	case syscall.EPERM:
		fmt.Println("PTRACE_BLOCKED")
	default:
		fmt.Printf("PTRACE_ERRNO_%d\n", int(errno))
	}
}
