package runner_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain redirects the audit trail to a temp file so the test suite never
// writes to the real ~/.ironrun/audit.jsonl. Individual tests may override
// IRONRUN_AUDIT_PATH with t.Setenv.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ironrun-runner-audit")
	if err == nil {
		os.Setenv("IRONRUN_AUDIT_PATH", filepath.Join(dir, "audit.jsonl"))
	} else {
		os.Setenv("IRONRUN_AUDIT", "off")
	}
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}
