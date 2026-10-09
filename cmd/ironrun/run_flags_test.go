package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/audit"
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

// A tampered audit log must stop `ironrun run` instead of silently disabling
// the audit trail for the run.
func TestRunRefusesTamperedAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	l, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Append(audit.Entry{CommandID: "deploy", ExitCode: 1})
	_ = l.Close()
	data, _ := os.ReadFile(logPath)
	_ = os.WriteFile(logPath, []byte(strings.Replace(string(data), `"exit_code":1`, `"exit_code":0`, 1)), 0o600)

	policyFile := filepath.Join(dir, "ironrun.yml")
	policy := "version: \"1\"\nprovider: passthrough\naudit_log: " + logPath + "\ncommands:\n  - id: greet\n    argv: [echo, hi]\n"
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := policyPath
	policyPath = policyFile
	t.Cleanup(func() { policyPath = previous })

	c := runCmd()
	c.SetArgs([]string{"no-such-command"})
	c.SilenceErrors, c.SilenceUsage = true, true
	err = c.Execute()
	if err == nil || !strings.Contains(err.Error(), "ironrun audit verify") || !strings.Contains(err.Error(), ".tampered") {
		t.Fatalf("run with tampered audit log must fail with inspect and recovery steps: %v", err)
	}
}
