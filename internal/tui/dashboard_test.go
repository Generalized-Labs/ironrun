package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/generalized-labs/ironrun/internal/envset"
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

func TestEnvironmentKeyValidation(t *testing.T) {
	for _, valid := range []string{"OPENAI_API_KEY", "_SESSION_TOKEN", "database2"} {
		if !validEnvironmentKey(valid) {
			t.Errorf("valid key rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "2TOKEN", "API-KEY", "HAS SPACE", "KEY=value"} {
		if validEnvironmentKey(invalid) {
			t.Errorf("invalid key accepted: %q", invalid)
		}
	}
}

func TestShortTerminalKeepsActionsVisibleAndInteractive(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\nprovider: passthrough\ncommands:\n  - id: test\n    argv: [echo, ok]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := New(root, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	m.width, m.height = 160, 16
	dev := envset.Set{Name: "dev"}
	m.env = &envset.Manager{Meta: envset.Metadata{Active: "dev", Sets: map[string]envset.Set{"dev": dev}}}
	m.environments = []envset.Set{dev}

	view := m.View().Content
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("dashboard is %d rows high in a %d-row terminal", got, m.height)
	}
	if !strings.Contains(view, "s add secret") {
		t.Fatal("short terminal clipped the action bar")
	}

	_, _ = m.Update(tea.KeyPressMsg(tea.Key{Code: 's', Text: "s"}))
	if m.mode != modeSecretKey {
		t.Fatalf("s key did not open secret entry: mode=%v", m.mode)
	}
	view = m.View().Content
	if got := lipgloss.Height(view); got > m.height {
		t.Fatalf("secret prompt is %d rows high in a %d-row terminal", got, m.height)
	}
	if !strings.Contains(view, "environment key to store") || !strings.Contains(view, "enter continue") {
		t.Fatal("secret-key prompt is not visible after pressing s")
	}
}
