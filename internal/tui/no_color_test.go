package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoColorWorkspaceEmitsNoANSIColorSequences(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\nprovider: passthrough\ncommands:\n  - id: test\n    argv: [echo, ok]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(root, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	m.width, m.height = 80, 24
	if view := m.View().Content; strings.Contains(view, "\x1b[38;") || strings.Contains(view, "\x1b[48;") {
		t.Fatalf("NO_COLOR view emitted color escapes: %q", view)
	}
}
