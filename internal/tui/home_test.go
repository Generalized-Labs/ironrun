package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/generalized-labs/ironrun/internal/project"
)

func TestHomeFitsSupportedTerminalSizesAndShowsExit(t *testing.T) {
	root := t.TempDir()
	store := &project.Store{Path: filepath.Join(t.TempDir(), "projects.json"), Now: time.Now}
	if _, err := store.Register(root); err != nil {
		t.Fatal(err)
	}
	for _, size := range [][2]int{{40, 12}, {80, 24}, {160, 16}, {200, 50}} {
		m, err := NewHome(store, false)
		if err != nil {
			t.Fatal(err)
		}
		m.width, m.height = size[0], size[1]
		view := m.View().Content
		if lipgloss.Height(view) > size[1] {
			t.Fatalf("%dx%d home rendered %d rows", size[0], size[1], lipgloss.Height(view))
		}
		for _, want := range []string{"PROJECTS", "Enter open", "q quit"} {
			if !strings.Contains(view, want) {
				t.Fatalf("%dx%d home hid %q:\n%s", size[0], size[1], want, view)
			}
		}
	}
}
