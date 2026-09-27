package main

import (
	"strings"
	"testing"
)

// The four Phase-0 hardening flags must exist on `ironrun run`, and --no-seal's
// help must state the seal's actual properties honestly (core dumps blocked;
// debugger attach NOT blocked — PR_SET_DUMPABLE cannot survive execve).
func TestRunCmd_HardeningFlags(t *testing.T) {
	c := runCmd()
	for _, name := range []string{"disable-seccomp", "disable-entropy-scan", "allow-pull-request-target", "no-seal"} {
		if c.Flags().Lookup(name) == nil {
			t.Errorf("runCmd missing --%s flag", name)
		}
	}
	noSeal := c.Flags().Lookup("no-seal")
	if noSeal == nil {
		t.Fatal("runCmd missing --no-seal flag")
	}
	usage := noSeal.Usage
	for _, want := range []string{"WEAKENS SECURITY", "RLIMIT_CORE", "core dump", "PR_SET_DUMPABLE cannot survive execve"} {
		if !strings.Contains(usage, want) {
			t.Errorf("--no-seal help missing %q; got: %q", want, usage)
		}
	}
	if strings.Contains(usage, "blocks your OWN debuggers") {
		t.Errorf("--no-seal help overclaims debugger-attach blocking: %q", usage)
	}
}
