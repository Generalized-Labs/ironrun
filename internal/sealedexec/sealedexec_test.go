//go:build linux

package sealedexec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Probe protocol: when this test binary is exec'd as the shim's TARGET with
// IRONRUN_SEALED_CHILD_PROBE set, TestMain inspects the target process itself
// instead of running tests:
//
//	"report"     -> prints "dumpable=N core_cur=M core_max=K" for the target
//	"filtertest" -> attempts ptrace(PTRACE_TRACEME) and prints whether it
//	                succeeded or was refused with errno
//
// This verifies the shim's effects end-to-end through the real path:
// parent -> shim (seal + optional seccomp) -> execve -> probe target.
const probeEnv = "IRONRUN_SEALED_CHILD_PROBE"

func TestMain(m *testing.M) {
	switch os.Getenv(probeEnv) {
	case "report":
		dumpable, _, _ := syscall.Syscall(unix.SYS_PRCTL, uintptr(unix.PR_GET_DUMPABLE), 0, 0)
		var lim unix.Rlimit
		_ = unix.Getrlimit(unix.RLIMIT_CORE, &lim)
		fmt.Printf("dumpable=%d core_cur=%d core_max=%d\n", dumpable, lim.Cur, lim.Max)
		os.Exit(0)
	case "filtertest":
		// PTRACE_TRACEME with no tracer succeeds on an unfiltered process and
		// is refused with EPERM under the shim's seccomp denylist.
		_, _, errno := syscall.Syscall(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0)
		if errno == 0 {
			fmt.Println("ptrace_traceme=ok")
		} else {
			fmt.Printf("ptrace_traceme=errno(%d)\n", int(errno))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// stubHardening replaces the filter/seal installers for one test and restores
// them afterwards. The returned pointers record whether each installer ran.
func stubHardening(t *testing.T, filterErr, sealErr error) (filterCalled, sealCalled *bool) {
	t.Helper()
	filterCalled = new(bool)
	sealCalled = new(bool)
	oldFilter, oldSeal := installFilter, installSeal
	installFilter = func() error { *filterCalled = true; return filterErr }
	installSeal = func() error { *sealCalled = true; return sealErr }
	t.Cleanup(func() { installFilter, installSeal = oldFilter, oldSeal })
	return filterCalled, sealCalled
}

func TestRun_MalformedInvocation(t *testing.T) {
	if got := run([]string{Sentinel}); got != exitBroken {
		t.Errorf("run([sentinel]) = %d, want %d", got, exitBroken)
	}
	if got := run([]string{Sentinel, "/bin/true"}); got != exitBroken {
		t.Errorf("run([sentinel, target]) = %d, want %d", got, exitBroken)
	}
}

func TestRun_FilterInstallFailureAborts(t *testing.T) {
	_, sealCalled := stubHardening(t, errors.New("seccomp unavailable"), nil)
	// Nonexistent target: the fail-closed refusal must happen BEFORE exec.
	if got := run([]string{Sentinel, "/nonexistent-target", "x"}); got != ExitFilterRefused {
		t.Errorf("run() with filter failure = %d, want fail-closed %d", got, ExitFilterRefused)
	}
	if *sealCalled {
		t.Error("seal must not run after a filter-install failure")
	}
}

func TestRun_SealInstallFailureAborts(t *testing.T) {
	filterCalled, _ := stubHardening(t, nil, errors.New("rlimit failed"))
	if got := run([]string{Sentinel, "/nonexistent-target", "x"}); got != ExitSealRefused {
		t.Errorf("run() with seal failure = %d, want fail-closed %d", got, ExitSealRefused)
	}
	if !*filterCalled {
		t.Error("filter should install before the seal is attempted")
	}
}

func TestRun_SkipSeccompSkipsFilterInstall(t *testing.T) {
	t.Setenv(EnvSkipSeccomp, "1")
	filterCalled, sealCalled := stubHardening(t, errors.New("must not be called"), nil)
	// Nonexistent target -> exec fails -> 126, after filter-skip + seal.
	if got := run([]string{Sentinel, "/nonexistent-target", "x"}); got != exitBroken {
		t.Errorf("run() with skip-seccomp = %d, want %d", got, exitBroken)
	}
	if *filterCalled {
		t.Error("filter installer ran despite IRONRUN_SKIP_SECCOMP=1")
	}
	if !*sealCalled {
		t.Error("seal should still run in skip-seccomp (seal-only) mode")
	}
}

func TestRun_NoSealSkipsSeal(t *testing.T) {
	t.Setenv(EnvNoSeal, "1")
	_, sealCalled := stubHardening(t, nil, nil)
	if got := run([]string{Sentinel, "/nonexistent-target", "x"}); got != exitBroken {
		t.Errorf("run() with no-seal = %d, want %d", got, exitBroken)
	}
	if *sealCalled {
		t.Error("seal installer ran despite IRONRUN_NO_SEAL=1")
	}
}

func TestRun_SealRunsByDefault(t *testing.T) {
	_, sealCalled := stubHardening(t, nil, nil)
	if got := run([]string{Sentinel, "/nonexistent-target", "x"}); got != exitBroken {
		t.Errorf("run() default = %d, want %d", got, exitBroken)
	}
	if !*sealCalled {
		t.Error("seal installer did not run by default")
	}
}

func TestStrippedEnv_RemovesShimSentinels(t *testing.T) {
	t.Setenv(EnvSentinel, "1")
	t.Setenv(EnvNoSeal, "1")
	t.Setenv(EnvSkipSeccomp, "1")
	t.Setenv("IRONRUN_PROBE_KEEPME", "yes")
	found := false
	for _, e := range strippedEnv() {
		switch {
		case strings.HasPrefix(e, EnvSentinel+"="),
			strings.HasPrefix(e, EnvNoSeal+"="),
			strings.HasPrefix(e, EnvSkipSeccomp+"="):
			t.Errorf("shim sentinel leaked into target env: %q", e)
		case e == "IRONRUN_PROBE_KEEPME=yes":
			found = true
		}
	}
	if !found {
		t.Error("ordinary env var was stripped from the target env")
	}
}

func TestSealChild_SetsNoCoreLimit(t *testing.T) {
	if err := sealChild(); err != nil {
		t.Fatalf("sealChild: %v", err)
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Errorf("RLIMIT_CORE after sealChild = {%d %d}, want {0 0}", lim.Cur, lim.Max)
	}
}

// runShimProbe executes this test binary as the sealed-exec shim (real seal,
// real seccomp filter unless skipFilter) with the probe as its target, and
// returns the probe's stdout.
func runShimProbe(t *testing.T, mode string, skipFilter bool) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Args = []string{Sentinel, self, "probe-target"}
	cmd.Env = append(os.Environ(), EnvSentinel+"=1", probeEnv+"="+mode)
	if skipFilter {
		cmd.Env = append(cmd.Env, EnvSkipSeccomp+"=1")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shim probe failed: %v\noutput: %s", err, out)
	}
	return string(out)
}

func TestShim_SealDisablesCoreDumps(t *testing.T) {
	out := runShimProbe(t, "report", false)
	if !strings.Contains(out, "core_cur=0 core_max=0") {
		t.Errorf("sealed child core limits not zeroed: %q", out)
	}
	// NOTE: this environment's ambient hard core limit is already 0, so this
	// assertion cannot distinguish the seal's doing from inheritance here; the
	// seal's prlimit64(RLIMIT_CORE, {0,0}) call was verified via strace, and
	// rlimits (signal_struct) survive execve by kernel design — the same
	// mechanism as `ulimit -c 0`.
}

func TestShim_DumpableNotPreservedAcrossExecve(t *testing.T) {
	out := runShimProbe(t, "report", false)
	// Documents the kernel behavior that forced PR_SET_DUMPABLE out of the
	// seal: the flag lives in the mm_struct, execve replaces the mm, so the
	// target always reads dumpable=1 no matter what the shim set. If this
	// assertion ever fails, a kernel behavior changed and the seal's threat
	// model should be revisited (a working pre-exec PR_SET_DUMPABLE would
	// then be worth re-adding).
	if !strings.Contains(out, "dumpable=1") {
		t.Errorf("expected dumpable=1 in execve'd target (kernel resets the flag), got: %q", out)
	}
}

func TestShim_FilterActiveInTarget(t *testing.T) {
	out := runShimProbe(t, "filtertest", false)
	// EPERM = the shim's seccomp denylist refused ptrace(2) INSIDE the
	// execve'd target: the filter survives execve.
	if !strings.Contains(out, "ptrace_traceme=errno(1)") {
		t.Errorf("expected seccomp to refuse ptrace in target, got: %q", out)
	}
}

func TestShim_SkipSeccompDisablesFilter(t *testing.T) {
	out := runShimProbe(t, "filtertest", true)
	if !strings.Contains(out, "ptrace_traceme=ok") {
		t.Errorf("expected ptrace to succeed with filter skipped, got: %q", out)
	}
	// The seal still applies in skip mode: core dumps stay disabled.
	out = runShimProbe(t, "report", true)
	if !strings.Contains(out, "core_cur=0 core_max=0") {
		t.Errorf("seal-only shim did not zero core limits: %q", out)
	}
}
