package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// If terminal masking is unavailable, ironrun must abort instead of reading
// the secret in cleartext — on ANY platform. These tests inject the
// disable/restore echo functions so they are deterministic in CI (no real
// terminal needed).
func TestReadSecretMaskedAbortsWhenMaskingFails(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	disableFails := func() error { return errors.New("no stty here") }
	restoreOK := func() error { return nil }

	value, err := readSecretMasked(devNull, disableFails, restoreOK)
	if err == nil {
		t.Fatal("readSecretMasked with failing mask: expected error, got none")
	}
	if value != "" {
		t.Fatalf("readSecretMasked with failing mask: expected no value, got %q", value)
	}
	if !strings.Contains(err.Error(), "refusing to read the secret in cleartext") {
		t.Fatalf("readSecretMasked with failing mask: unexpected error: %v", err)
	}
}

func TestReadSecretMaskedSuccessPath(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	noop := func() error { return nil }
	value, err := readSecretMasked(devNull, noop, noop)
	if err != nil {
		t.Fatalf("readSecretMasked with working mask: unexpected error: %v", err)
	}
	if value != "" {
		t.Fatalf("readSecretMasked with working mask: expected empty value from /dev/null, got %q", value)
	}
}

// TestDisableTerminalEcho_RealTerminal exercises the REAL stty path under a
// pty. Regression test: disableTerminalEcho used to run stty with nil stdin
// (Go hands nil-stdin children /dev/null), so stty always failed — even on a
// real terminal — and every interactive masked read aborted. The unit tests
// above inject fake mask functions, so only this test covers the real path.
// Skipped where no pty can be allocated.
func TestDisableTerminalEcho_RealTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stty is unavailable on Windows by design")
	}
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("no `script` utility available for pty allocation")
	}
	helper := os.Args[0] + " -test.run=TestSttyPtyHelper"
	cmd := exec.Command("script", "-qec", helper, "/dev/null")
	cmd.Env = append(os.Environ(), "IRONRUN_STTY_PTY_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real disableTerminalEcho under pty failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "STTY-OK") {
		t.Fatalf("expected STTY-OK from pty helper, got:\n%s", out)
	}
}

// TestSttyPtyHelper is not a real test: it runs inside the pty allocated by
// TestDisableTerminalEcho_RealTerminal and exercises the real package-level
// disable/restoreTerminalEcho functions against a genuine terminal.
func TestSttyPtyHelper(t *testing.T) {
	if os.Getenv("IRONRUN_STTY_PTY_HELPER") != "1" {
		return
	}
	if err := disableTerminalEcho(); err != nil {
		fmt.Fprintf(os.Stderr, "STTY-FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("STTY-OK")
	if err := restoreTerminalEcho(); err != nil {
		fmt.Fprintf(os.Stderr, "STTY-RESTORE-FAIL: %v\n", err)
		os.Exit(1)
	}
}
