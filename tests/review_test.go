package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runIron(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	bin := buildBinary(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestReviewApproveReject(t *testing.T) {
	dir := t.TempDir()
	policy := `version: "1"
provider: passthrough
allow_proposals: true
commands:
  - id: hello
    argv: [echo, hi]
`
	if err := os.WriteFile(filepath.Join(dir, "ironrun.yml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	mkPending := func(content string) {
		if err := os.MkdirAll(filepath.Join(dir, ".ironrun"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".ironrun", "pending.yml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	policyPath := filepath.Join(dir, "ironrun.yml")

	// review surfaces a staged proposal (argv + reason).
	mkPending("proposals:\n  - id: list-files\n    argv: [ls, -la]\n    reason: inspect output\n    status: pending\n")
	out, err := runIron(t, dir, "review")
	if err != nil {
		t.Fatalf("review: %v\n%s", err, out)
	}
	if !strings.Contains(out, "list-files") || !strings.Contains(out, "ls -la") {
		t.Errorf("review output missing proposal: %s", out)
	}

	// approve promotes it into the policy and clears it from pending; then it runs.
	if out, err := runIron(t, dir, "approve", "list-files", "--yes"); err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	pol, _ := os.ReadFile(policyPath)
	if !strings.Contains(string(pol), "id: list-files") {
		t.Errorf("approved command not added to policy: %s", pol)
	}
	if out, err := runIron(t, dir, "run", "list-files"); err != nil {
		t.Errorf("approved command should now run: %v\n%s", err, out)
	}

	// approve REFUSES a shell-argv proposal and leaves the policy untouched.
	mkPending("proposals:\n  - id: shellcmd\n    argv: [bash, -c, \"echo hi\"]\n    status: pending\n")
	polBefore, _ := os.ReadFile(policyPath)
	if out, err := runIron(t, dir, "approve", "shellcmd", "--yes"); err == nil {
		t.Errorf("expected approve to refuse a shell argv, got success:\n%s", out)
	}
	polAfter, _ := os.ReadFile(policyPath)
	if string(polBefore) != string(polAfter) {
		t.Error("policy changed despite a refused shell approve")
	}

	// reject removes the proposal without touching the policy.
	mkPending("proposals:\n  - id: dropme\n    argv: [ls]\n    status: pending\n")
	if out, err := runIron(t, dir, "reject", "dropme"); err != nil {
		t.Errorf("reject: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ".ironrun", "pending.yml"))
	if strings.Contains(string(data), "dropme") {
		t.Errorf("rejected proposal still present: %s", data)
	}
}
