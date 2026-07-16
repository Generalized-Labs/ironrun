package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/pending"
	"github.com/generalized-labs/ironrun/internal/project"
)

type homeTab int

const (
	homeProjects homeTab = iota
	homeInbox
)

type InboxItem struct {
	Project  project.Project
	Request  access.Request
	Proposal *pending.Proposal
}

type HomeModel struct {
	registry     *project.Store
	projects     []project.Project
	inbox        []InboxItem
	tab          homeTab
	cursor       int
	width        int
	height       int
	showHelp     bool
	showPalette  bool
	message      string
	selectedPath string
	snapshot     string
}

type homeChangedMsg struct{}

func RunGlobal(registry *project.Store, focusInbox bool) (string, error) {
	m, err := NewHome(registry, focusInbox)
	if err != nil {
		return "", err
	}
	result, err := tea.NewProgram(m).Run()
	if err != nil {
		return "", err
	}
	if final, ok := result.(*HomeModel); ok {
		return final.selectedPath, nil
	}
	return "", nil
}

func NewHome(registry *project.Store, focusInbox bool) (*HomeModel, error) {
	m := &HomeModel{registry: registry}
	if focusInbox {
		m.tab = homeInbox
	}
	if err := m.reloadHome(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *HomeModel) Init() tea.Cmd { return watchHome(m.registry, m.snapshot) }

func (m *HomeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case homeChangedMsg:
		if err := m.reloadHome(); err != nil {
			m.message = "Refresh failed: " + safeError(err)
		}
		return m, watchHome(m.registry, m.snapshot)
	case tea.KeyPressMsg:
		if m.showHelp || m.showPalette {
			switch msg.String() {
			case "esc", "?", "/", "q":
				m.showHelp, m.showPalette = false, false
			}
			return m, nil
		}
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "?":
			m.showHelp = true
		case "/":
			m.showPalette = true
		case "tab", "right", "l":
			m.tab = (m.tab + 1) % 2
			m.cursor = 0
		case "shift+tab", "left", "h":
			m.tab = (m.tab + 1) % 2
			m.cursor = 0
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor+1 < m.itemCount() {
				m.cursor++
			}
		case "r":
			if err := m.reloadHome(); err != nil {
				m.message = "Refresh failed: " + safeError(err)
			} else {
				m.message = "Workspace refreshed"
			}
		case "enter":
			if path := m.selectedProjectPath(); path != "" {
				if _, err := os.Stat(path); err != nil {
					m.message = "Checkout is missing. Repair or remove it with `ironrun projects`."
					return m, nil
				}
				m.selectedPath = path
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m *HomeModel) View() tea.View {
	width, height := m.width, m.height
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	var b strings.Builder
	b.WriteString("IRONRUN  ENVIRONMENT WORKSPACE\n")
	b.WriteString(strings.Repeat("─", max(1, min(width, 72))))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%s  %s\n\n", tabLabel(m.tab == homeProjects, "PROJECTS", len(m.projects)), tabLabel(m.tab == homeInbox, "INBOX", len(m.inbox)))
	if m.showHelp {
		b.WriteString("Help\n  ↑↓ choose   Enter open   Tab switch view\n  / actions   r refresh   Esc or q quit\n")
		return croppedHomeView(b.String(), height)
	}
	if m.showPalette {
		b.WriteString("Actions\n  Open selected project\n  Open waiting request\n  Refresh workspace\n  Run `ironrun open PATH` to register another checkout\n")
		return croppedHomeView(b.String(), height)
	}
	if m.tab == homeInbox {
		m.renderInbox(&b, height-8)
	} else {
		m.renderProjects(&b, height-8)
	}
	if m.message != "" {
		b.WriteString("\n" + m.message + "\n")
	}
	b.WriteString("\n↑↓ choose  Enter open  Tab switch  / actions  ? help  q quit")
	return croppedHomeView(b.String(), height)
}

func (m *HomeModel) renderProjects(b *strings.Builder, rows int) {
	if len(m.projects) == 0 {
		b.WriteString("No projects registered.\n\nRun `ironrun open PATH` inside a project to add it.")
		return
	}
	start, end := visibleRange(m.cursor, len(m.projects), max(1, rows))
	for i := start; i < end; i++ {
		p := m.projects[i]
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		state := "ready"
		if _, err := os.Stat(p.Path); err != nil {
			state = "missing checkout"
		} else if !p.Configured {
			state = "setup needed"
		}
		fmt.Fprintf(b, "%s%s  %s\n    %s  [%s]\n", marker, p.Name, shortProjectID(p.ID), p.Path, state)
	}
}

func (m *HomeModel) renderInbox(b *strings.Builder, rows int) {
	if len(m.inbox) == 0 {
		b.WriteString("No waiting human actions.\n\nAgent requests will appear here automatically.")
		return
	}
	start, end := visibleRange(m.cursor, len(m.inbox), max(1, rows/2))
	for i := start; i < end; i++ {
		item := m.inbox[i]
		marker := "  "
		if i == m.cursor {
			marker = "> "
		}
		if item.Proposal != nil {
			fmt.Fprintf(b, "%s%s needs command approval\n    %s · argv %q\n", marker, item.Project.Name, item.Proposal.ID, item.Proposal.Argv)
			continue
		}
		detail := strings.Join(item.Request.Commands, ", ")
		if item.Request.Kind == access.RequestSecret {
			detail = item.Request.SecretAlias + " (missing)"
		} else if item.Request.Kind == access.RequestWorkspace {
			detail = "trusted session · " + strings.Join(item.Request.FirstArgv, " ")
		}
		fmt.Fprintf(b, "%s%s needs %s\n    %s · env %s · expires %s\n", marker, item.Project.Name, item.Request.Kind, detail, item.Request.Environment, item.Request.ExpiresAt.Local().Format("15:04"))
	}
}

func (m *HomeModel) reloadHome() error {
	projects, err := m.registry.List()
	if err != nil {
		return err
	}
	var inbox []InboxItem
	for _, p := range projects {
		if _, err := os.Stat(p.Path); err != nil {
			continue
		}
		manager, err := access.Open(p.Path)
		if err != nil {
			continue
		}
		requests, err := manager.Requests()
		if err != nil {
			continue
		}
		for _, request := range requests {
			if request.Status == access.StatusPending {
				inbox = append(inbox, InboxItem{Project: p, Request: request})
			}
		}
		policyPath := filepath.Join(p.Path, "ironrun.yml")
		if proposals, loadErr := pending.Load(pending.Path(policyPath)); loadErr == nil {
			for i := range proposals.Proposals {
				proposal := proposals.Proposals[i]
				inbox = append(inbox, InboxItem{Project: p, Proposal: &proposal})
			}
		}
	}
	sort.SliceStable(inbox, func(i, j int) bool {
		if inbox[i].Proposal != nil && inbox[j].Proposal == nil {
			return true
		}
		if inbox[i].Proposal == nil && inbox[j].Proposal != nil {
			return false
		}
		return inbox[i].Request.CreatedAt.Before(inbox[j].Request.CreatedAt)
	})
	m.projects, m.inbox = projects, inbox
	if m.cursor >= m.itemCount() {
		m.cursor = max(0, m.itemCount()-1)
	}
	m.snapshot = homeSnapshot(m.registry, projects)
	return nil
}

func (m *HomeModel) itemCount() int {
	if m.tab == homeInbox {
		return len(m.inbox)
	}
	return len(m.projects)
}

func (m *HomeModel) selectedProjectPath() string {
	if m.tab == homeInbox {
		if m.cursor < len(m.inbox) {
			return m.inbox[m.cursor].Project.Path
		}
		return ""
	}
	if m.cursor < len(m.projects) {
		return m.projects[m.cursor].Path
	}
	return ""
}

func watchHome(registry *project.Store, snapshot string) tea.Cmd {
	return func() tea.Msg {
		for {
			time.Sleep(200 * time.Millisecond)
			projects, err := registry.List()
			if err != nil || homeSnapshot(registry, projects) != snapshot {
				return homeChangedMsg{}
			}
		}
	}
}

func homeSnapshot(registry *project.Store, projects []project.Project) string {
	var b strings.Builder
	for _, path := range append([]string{registry.Path}, projectStatePaths(projects)...) {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(&b, "%s:missing;", path)
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", path, info.ModTime().UnixNano(), info.Size())
	}
	return b.String()
}

func projectStatePaths(projects []project.Project) []string {
	paths := make([]string, 0, len(projects)*2)
	for _, p := range projects {
		policyPath := filepath.Join(p.Path, "ironrun.yml")
		paths = append(paths, filepath.Join(p.Path, ".ironrun", "access.json"), policyPath, pending.Path(policyPath))
	}
	return paths
}

func tabLabel(active bool, label string, count int) string {
	if active {
		return fmt.Sprintf("[%s %d]", label, count)
	}
	return fmt.Sprintf(" %s %d ", label, count)
}

func visibleRange(cursor, count, capacity int) (int, int) {
	start := max(0, cursor-capacity+1)
	end := min(count, start+capacity)
	return start, end
}

func shortProjectID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func croppedHomeView(content string, height int) tea.View {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	view := tea.NewView(strings.Join(lines, "\n"))
	view.AltScreen = true
	return view
}
