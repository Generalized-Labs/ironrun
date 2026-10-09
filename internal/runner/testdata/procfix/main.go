// procfix is a multi-mode test fixture for runner process-control tests.
// It is Unix-only (uses syscall.Kill for the self-signal mode); callers that
// need it skip on other platforms.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {

	case "spawn-grandchild":
		// argv: spawn-grandchild <marker>. Start a grandchild (same process
		// group) that sleeps then writes <marker>, while this parent blocks.
		// Group teardown must kill the grandchild before it writes the marker.
		gc := exec.Command(os.Args[0], "sleep-write", os.Args[2])
		_ = gc.Start()
		time.Sleep(60 * time.Second)

	case "sleep-write":
		time.Sleep(3 * time.Second)
		_ = os.WriteFile(os.Args[2], []byte("GRANDCHILD_SURVIVED"), 0o600)

	case "hold-pipe":
		// Spawn a grandchild that inherits this process's stdout and holds it
		// open while the parent exits immediately. Without WaitDelay, Wait would
		// block on the still-open pipe until the grandchild finally exits.
		gc := exec.Command(os.Args[0], "sleep-silent")
		gc.Stdout = os.Stdout
		gc.Stderr = os.Stderr
		_ = gc.Start()
		fmt.Println("parent-done")

	case "sleep-silent":
		time.Sleep(60 * time.Second)

	case "stream":
		// Emit output forever, so a broken output sink is the only thing that
		// can end the run.
		for {
			fmt.Println("streaming-line")
			time.Sleep(10 * time.Millisecond)
		}

	case "exit":
		// argv: exit <code>. Exit with the given status code.
		code, _ := strconv.Atoi(os.Args[2])
		os.Exit(code)

	case "self-signal":
		// argv: self-signal <signo>. Terminate self with the given signal.
		sig, _ := strconv.Atoi(os.Args[2])
		_ = syscall.Kill(os.Getpid(), syscall.Signal(sig))
		time.Sleep(5 * time.Second)

	case "emit":
		// argv: emit <n>. Write exactly n bytes to stdout.
		n, _ := strconv.Atoi(os.Args[2])
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = 'x'
		}
		_, _ = os.Stdout.Write(buf)

	case "fork-exec":
		// Spawn a child process and report success — proves the sandbox allows
		// fork/exec of subprocesses.
		out, err := exec.Command("/bin/echo", "child-ok").Output()
		if err != nil {
			fmt.Println("FORK_FAILED:", err)
			os.Exit(1)
		}
		fmt.Print("FORK_", string(out))

	default:
		os.Exit(2)
	}
}
