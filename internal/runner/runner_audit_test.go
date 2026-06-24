package runner_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/runner"
)

// A sealed run must write exactly one audit line, and that line must NEVER
// contain the secret value.
func TestRun_WritesSecretFreeAudit(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("IRONRUN_AUDIT_PATH", auditPath)
	t.Setenv("IRONRUN_AUDIT", "")

	secret := "ironrun-audit-secret-value"
	cmd := makeCmd("printenv", "", "printenv", "IRONRUN_SECRET")
	_, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:   &bytes.Buffer{},
		Stderr:   &bytes.Buffer{},
		Secrets:  map[string]string{"IRONRUN_SECRET": secret},
		Provider: "env",
		Source:   "cli",
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	s := string(data)

	if strings.Contains(s, secret) {
		t.Errorf("SECRET VALUE LEAKED INTO AUDIT LOG: %s", s)
	}
	for want := range map[string]struct{}{
		`"command_id":"printenv"`: {},
		`"source":"cli"`:          {},
		`"provider":"env"`:        {},
		`"redactions":1`:          {},
		`"argv_hash":`:            {},
	} {
		if !strings.Contains(s, want) {
			t.Errorf("audit line missing %s\ngot: %s", want, s)
		}
	}
}
