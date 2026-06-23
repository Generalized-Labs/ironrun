package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit_WriteVerifyAndTamper(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	policy := writeTempPolicyFile(t, `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`)
	env := append(os.Environ(), "IRONRUN_AUDIT_LOG="+logPath, "IRONRUN_SECCOMP=off")

	run := exec.Command(cliBin, "--policy", policy, "run", "greet")
	run.Env = env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run greet failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(data), `"command_id":"greet"`) {
		t.Errorf("expected greet entry in audit log, got: %s", data)
	}

	verify := exec.Command(cliBin, "--policy", policy, "audit", "verify")
	verify.Env = env
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("audit verify should pass on intact log: %v\n%s", err, out)
	} else if !strings.Contains(string(out), "intact") {
		t.Errorf("expected 'intact' in verify output, got: %s", out)
	}

	// Tamper with the recorded exit code without recomputing the hash.
	tampered := strings.Replace(string(data), `"exit_code":0`, `"exit_code":7`, 1)
	if tampered == string(data) {
		t.Fatalf("setup: could not find exit_code to tamper in: %s", data)
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	verify2 := exec.Command(cliBin, "--policy", policy, "audit", "verify")
	verify2.Env = env
	out, err := verify2.CombinedOutput()
	if err == nil {
		t.Errorf("audit verify should fail after tampering, got success: %s", out)
	}
	if !strings.Contains(string(out), "TAMPER") {
		t.Errorf("expected 'TAMPER' in verify output, got: %s", out)
	}
}

// TestAudit_NoSecretValues is the critical guarantee: the audit log records the
// secret NAME but never its VALUE.
func TestAudit_NoSecretValues(t *testing.T) {
	const canary = "ironrun-audit-canary-Zq8mP4"
	logPath := filepath.Join(t.TempDir(), "audit.log")
	policy := writeTempPolicyFile(t, `version: "1"
provider: env
commands:
  - id: dump
    argv: [printenv, MYSECRET]
    ttl: 5s
    no_network: true
    env:
      MYSECRET: env:MYSECRET
`)
	// Seccomp is irrelevant to what this test checks (audit content), so disable
	// it for determinism — the dedicated seccomp tests cover that path.
	env := append(os.Environ(), "IRONRUN_AUDIT_LOG="+logPath, "MYSECRET="+canary, "IRONRUN_SECCOMP=off")

	run := exec.Command(cliBin, "--policy", policy, "run", "dump")
	run.Env = env
	out, runErr := run.CombinedOutput() // printenv exits 0; output is redacted
	if strings.Contains(string(out), canary) {
		t.Errorf("canary value leaked in command output: %s", out)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v (run err=%v, output=%s)", err, runErr, out)
	}
	if strings.Contains(string(data), canary) {
		t.Errorf("SECURITY: canary VALUE found in audit log: %s", data)
	}
	if !strings.Contains(string(data), "MYSECRET") {
		t.Errorf("expected secret NAME 'MYSECRET' in audit log; log=%q runErr=%v output=%s", data, runErr, out)
	}
}
