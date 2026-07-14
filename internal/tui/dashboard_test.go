package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardMasksSecretInputAndRendersMetadataOnly(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	policy := `version: "1"
provider: passthrough
secrets:
  openai:
    env: OPENAI_API_KEY
    store: envfile
    allow: [greet]
commands:
  - id: greet
    argv: [echo, hello]
    secrets: [openai]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(root, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.access.CreateSecretRequest("session-a", "default", "openai", "OPENAI_API_KEY", "needed for tests"); err != nil {
		t.Fatal(err)
	}
	if err := m.reload(); err != nil {
		t.Fatal(err)
	}
	m.width, m.height = 110, 32
	m.focus = focusRequests
	m.mode = modeSecret
	m.message = "Enter openai locally"
	m.input.SetValue("sk-never-render-this")
	_ = m.input.Focus()
	view := m.View().Content
	if strings.Contains(view, "sk-never-render-this") {
		t.Fatal("dashboard rendered a plaintext secret")
	}
	if !strings.Contains(view, "OPENAI") && !strings.Contains(view, "openai") {
		t.Fatal("dashboard should render safe alias metadata")
	}
}
