// Package tui provides Ironrun's value-blind terminal control room. It renders
// secret names and state but never reads values except inside a masked input
// that is immediately committed to the encrypted store.
package tui

import (
	"errors"
	"fmt"
	"image/color"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

const (
	focusEnvironments = iota
	focusRequests
	focusLeases
)

type mode int

const (
	modeNormal mode = iota
	modeApprove
	modeDeny
	modeRevoke
	modeSecret
)

type Model struct {
	root       string
	policyPath string
	policy     *policy.File
	access     *access.Manager
	env        *envset.Manager

	environments []envset.Set
	requests     []access.Request
	leases       []access.Lease
	focus        int
	cursor       [3]int
	mode         mode
	input        textinput.Model
	width        int
	height       int
	dark         bool
	message      string
	isError      bool
}

type refreshMsg struct{}

func Run(policyPath string) error {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		return err
	}
	m, err := New(filepath.Dir(abs), abs)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m).Run()
	return err
}

func New(root, policyPath string) (*Model, error) {
	f, err := policy.Load(policyPath)
	if err != nil {
		return nil, err
	}
	requests, err := access.Open(root)
	if err != nil {
		return nil, err
	}
	input := textinput.New()
	input.Prompt = "  › "
	input.Placeholder = "paste secret value"
	input.EchoMode = textinput.EchoPassword
	input.EchoCharacter = '•'
	input.CharLimit = 16 * 1024
	input.SetWidth(54)
	m := &Model{
		root: root, policyPath: policyPath, policy: f, access: requests,
		input: input, dark: true,
	}
	if f.EnvironmentSet == "active" {
		m.env, err = envset.Open(root)
		if err != nil {
			return nil, err
		}
	}
	if err := m.reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(tea.RequestBackgroundColor, tea.Tick(time.Second, func(time.Time) tea.Msg { return refreshMsg{} }))
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.BackgroundColorMsg:
		m.dark = msg.IsDark()
		return m, nil
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.input.SetWidth(max(24, min(54, msg.Width-12)))
		return m, nil
	case refreshMsg:
		return m, tea.Tick(time.Second, func(time.Time) tea.Msg { return refreshMsg{} })
	case tea.KeyPressMsg:
		if m.mode == modeSecret {
			return m.updateSecretInput(msg)
		}
		if m.mode != modeNormal {
			return m.updateConfirmation(msg)
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "right", "l":
			m.focus = (m.focus + 1) % 3
		case "shift+tab", "left", "h":
			m.focus = (m.focus + 2) % 3
		case "up", "k":
			if m.cursor[m.focus] > 0 {
				m.cursor[m.focus]--
			}
		case "down", "j":
			limit := m.focusLength(m.focus)
			if m.cursor[m.focus]+1 < limit {
				m.cursor[m.focus]++
			}
		case "u":
			m.useSelectedEnvironment()
		case "a", "enter":
			m.beginPrimaryAction()
		case "d":
			if m.focus == focusRequests && len(m.requests) > 0 {
				m.mode = modeDeny
				m.message = "Deny this pending request?"
				m.isError = false
			}
		case "r":
			if m.focus == focusLeases && len(m.leases) > 0 && m.selectedLease().RevokedAt == nil {
				m.mode = modeRevoke
				m.message = "Revoke this lease immediately?"
				m.isError = false
			} else {
				m.refreshWithMessage("State refreshed", false)
			}
		case "g":
			m.refreshWithMessage("State refreshed", false)
		}
	}
	return m, nil
}

func (m *Model) updateSecretInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.input.SetValue("")
		m.input.Blur()
		m.mode = modeNormal
		m.message = "Secret entry cancelled"
		return m, nil
	case "enter":
		value := m.input.Value()
		m.input.SetValue("")
		m.input.Blur()
		if value == "" {
			m.message, m.isError = "Secret value cannot be empty", true
			return m, nil
		}
		request := m.selectedRequest()
		err := m.storeSecret(request, value)
		value = "" // release the last local reference promptly
		m.mode = modeNormal
		if err != nil {
			m.message, m.isError = "Could not fulfill request: "+safeError(err), true
			return m, nil
		}
		m.refreshWithMessage("Secret stored locally; MCP received no plaintext", false)
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) updateConfirmation(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc", "n":
		m.mode = modeNormal
		m.message = "Action cancelled"
		return m, nil
	case "y", "enter":
		var err error
		switch m.mode {
		case modeApprove:
			_, err = m.access.ApproveLease(m.selectedRequest().ID, 0)
		case modeDeny:
			err = m.access.Deny(m.selectedRequest().ID)
		case modeRevoke:
			err = m.access.Revoke(m.selectedLease().ID, "")
		}
		m.mode = modeNormal
		if err != nil {
			m.message, m.isError = safeError(err), true
		} else {
			m.refreshWithMessage("Access state updated", false)
		}
	}
	return m, nil
}

func (m *Model) beginPrimaryAction() {
	switch m.focus {
	case focusEnvironments:
		m.useSelectedEnvironment()
	case focusRequests:
		if len(m.requests) == 0 {
			return
		}
		request := m.selectedRequest()
		if request.Kind == access.RequestSecret {
			m.mode = modeSecret
			m.message = "Enter " + request.SecretAlias + " locally"
			m.input.Reset()
			_ = m.input.Focus()
		} else {
			m.mode = modeApprove
			m.message = "Approve this lease until " + time.Now().Add(request.RequestedTTL).Format("15:04") + "?"
		}
	case focusLeases:
		if len(m.leases) > 0 && m.selectedLease().RevokedAt == nil {
			m.mode = modeRevoke
			m.message = "Revoke this lease immediately?"
		}
	}
}

func (m *Model) useSelectedEnvironment() {
	if m.env == nil || len(m.environments) == 0 {
		m.message, m.isError = "This policy does not use project environments", true
		return
	}
	selected := m.environments[m.cursor[focusEnvironments]].Name
	if err := m.env.Use(selected); err != nil {
		m.message, m.isError = safeError(err), true
		return
	}
	m.refreshWithMessage("Active environment switched to "+selected, false)
}

func (m *Model) storeSecret(request access.Request, value string) error {
	decl, ok := m.policy.Secrets[request.SecretAlias]
	if !ok || decl.Env != request.SecretKey {
		return errors.New("request no longer matches the policy")
	}
	_, err := m.access.FulfillSecretWith(request.ID, func(locked access.Request) error {
		if m.policy.EnvironmentSet == "active" {
			if m.env == nil {
				return errors.New("environment vault unavailable")
			}
			return m.env.Put(locked.Environment, locked.SecretKey, value)
		}
		store, err := secretstore.Open(m.policyPath, decl.Store)
		if err != nil {
			return err
		}
		return store.Set(locked.SecretAlias, value)
	})
	return err
}

func (m *Model) reload() error {
	requests, err := m.access.Requests()
	if err != nil {
		return err
	}
	m.requests = m.requests[:0]
	for _, request := range requests {
		if request.Status == access.StatusPending {
			m.requests = append(m.requests, request)
		}
	}
	m.leases, err = m.access.Leases("")
	if err != nil {
		return err
	}
	if m.env != nil {
		// Reopen to observe CLI changes while the dashboard is running.
		m.env, err = envset.Open(m.root)
		if err != nil {
			return err
		}
		m.environments = m.environments[:0]
		for _, name := range m.env.Names() {
			set, _ := m.env.Set(name)
			m.environments = append(m.environments, set)
		}
	}
	for i := range m.cursor {
		limit := m.focusLength(i)
		if limit == 0 {
			m.cursor[i] = 0
		} else if m.cursor[i] >= limit {
			m.cursor[i] = limit - 1
		}
	}
	return nil
}

func (m *Model) refreshWithMessage(message string, isError bool) {
	_ = m.reload()
	m.message, m.isError = message, isError
}

func (m *Model) focusLength(focus int) int {
	switch focus {
	case focusEnvironments:
		return len(m.environments)
	case focusRequests:
		return len(m.requests)
	default:
		return len(m.leases)
	}
}

func (m *Model) selectedRequest() access.Request {
	if len(m.requests) == 0 {
		return access.Request{}
	}
	return m.requests[m.cursor[focusRequests]]
}
func (m *Model) selectedLease() access.Lease {
	if len(m.leases) == 0 {
		return access.Lease{}
	}
	return m.leases[m.cursor[focusLeases]]
}

func (m *Model) View() tea.View {
	styles := newStyles(m.dark)
	width := m.width
	if width <= 0 {
		width = 100
	}
	header := m.renderHeader(styles, width)
	stats := m.renderStats(styles, width)
	panels := m.renderPanels(styles, width)
	footer := m.renderFooter(styles, width)
	content := lipgloss.JoinVertical(lipgloss.Left, header, stats, panels, footer)
	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m *Model) renderHeader(s styles, width int) string {
	brand := s.brand.Render("IRONRUN") + " " + s.brandSub.Render("LOCAL AGENT VAULT")
	identity := m.root
	if m.env != nil && m.env.Meta.Identity.RemoteURL != "" {
		identity = m.env.Meta.Identity.RemoteURL
	}
	right := s.muted.Render(trimMiddle(identity, max(20, width-lipgloss.Width(brand)-8)))
	gap := max(1, width-lipgloss.Width(brand)-lipgloss.Width(right)-4)
	return s.header.Width(width).Render(brand + strings.Repeat(" ", gap) + right)
}

func (m *Model) renderStats(s styles, width int) string {
	active := "default"
	if m.env != nil && m.env.Meta.Active != "" {
		active = m.env.Meta.Active
	}
	activeLeases := 0
	for _, lease := range m.leases {
		if lease.RevokedAt == nil && time.Now().Before(lease.ExpiresAt) {
			activeLeases++
		}
	}
	items := []string{
		s.stat.Render("● ENCRYPTED") + " " + s.value.Render("project vault"),
		s.label.Render("ENV") + " " + s.value.Render(active),
		s.label.Render("REQUESTS") + " " + s.value.Render(fmt.Sprint(len(m.requests))),
		s.label.Render("LEASES") + " " + s.value.Render(fmt.Sprint(activeLeases)),
	}
	return s.stats.Width(width).Render(strings.Join(items, "   "))
}

func (m *Model) renderPanels(s styles, width int) string {
	if width < 86 {
		return lipgloss.JoinVertical(lipgloss.Left,
			m.renderEnvironments(s, width), m.renderRequests(s, width), m.renderLeases(s, width))
	}
	inner := width - 4
	left := max(24, inner*27/100)
	middle := max(32, inner*38/100)
	right := max(28, inner-left-middle)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		m.renderEnvironments(s, left), m.renderRequests(s, middle), m.renderLeases(s, right))
}

func (m *Model) renderEnvironments(s styles, width int) string {
	rows := make([]string, 0, len(m.environments)+1)
	if len(m.environments) == 0 {
		rows = append(rows, s.muted.Render("No project sets\nprovider-backed default"))
	}
	for i, environment := range m.environments {
		marker := "○"
		if m.env != nil && m.env.Meta.Active == environment.Name {
			marker = "●"
		}
		expiry := "persistent"
		if environment.ExpiresAt != nil {
			expiry = humanTTL(time.Until(*environment.ExpiresAt))
		}
		row := fmt.Sprintf("%s %-14s\n  %d keys · %s", marker, environment.Name, len(environment.Keys), expiry)
		rows = append(rows, s.row(m.focus == focusEnvironments && i == m.cursor[focusEnvironments]).Render(row))
	}
	return s.panel(m.focus == focusEnvironments, width).Render(s.panelTitle.Render("01  ENVIRONMENTS") + "\n\n" + strings.Join(rows, "\n"))
}

func (m *Model) renderRequests(s styles, width int) string {
	rows := make([]string, 0, len(m.requests)+1)
	if len(m.requests) == 0 {
		rows = append(rows, s.empty.Render("✓ No pending requests\nAgents are waiting behind policy."))
	}
	for i, request := range m.requests {
		kind := strings.ToUpper(string(request.Kind))
		detail := request.SecretAlias
		if request.Kind == access.RequestLease {
			detail = strings.Join(request.Commands, ", ")
		}
		row := fmt.Sprintf("%s  %s\n%s\n%s · expires %s", s.requestKind.Render(kind), shortID(request.ID),
			detail, shortID(request.SessionID), humanTTL(time.Until(request.ExpiresAt)))
		rows = append(rows, s.row(m.focus == focusRequests && i == m.cursor[focusRequests]).Render(row))
	}
	return s.panel(m.focus == focusRequests, width).Render(s.panelTitle.Render("02  AGENT INBOX") + "\n\n" + strings.Join(rows, "\n"))
}

func (m *Model) renderLeases(s styles, width int) string {
	rows := make([]string, 0, len(m.leases)+1)
	if len(m.leases) == 0 {
		rows = append(rows, s.muted.Render("No leases issued"))
	}
	sort.SliceStable(m.leases, func(i, j int) bool { return m.leases[i].ExpiresAt.After(m.leases[j].ExpiresAt) })
	for i, lease := range m.leases {
		status := "ACTIVE"
		color := s.active
		if lease.RevokedAt != nil {
			status, color = "REVOKED", s.danger
		} else if time.Now().After(lease.ExpiresAt) {
			status, color = "EXPIRED", s.muted
		}
		row := fmt.Sprintf("%s  %s\n%s · %s\n%s", color.Render(status), shortID(lease.ID),
			lease.Environment, shortID(lease.SessionID), strings.Join(lease.Commands, ", "))
		rows = append(rows, s.row(m.focus == focusLeases && i == m.cursor[focusLeases]).Render(row))
	}
	return s.panel(m.focus == focusLeases, width).Render(s.panelTitle.Render("03  LIVE LEASES") + "\n\n" + strings.Join(rows, "\n"))
}

func (m *Model) renderFooter(s styles, width int) string {
	if m.mode == modeSecret {
		box := s.modal.Width(max(30, min(66, width-6))).Render(
			s.modalTitle.Render("SEALED INPUT") + "\n" + s.muted.Render(m.message) + "\n\n" + m.input.View() +
				"\n\n" + s.help.Render("enter store locally  ·  esc cancel  ·  value never rendered"))
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, box)
	}
	if m.mode != modeNormal {
		box := s.modal.Width(max(30, min(64, width-6))).Render(
			s.modalTitle.Render("HUMAN APPROVAL") + "\n\n" + m.message + "\n\n" +
				s.help.Render("y / enter confirm    n / esc cancel"))
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, box)
	}
	message := m.message
	if message == "" {
		message = "tab move  ·  j/k select  ·  enter act  ·  d deny  ·  r revoke  ·  u use env  ·  g refresh  ·  q quit"
	}
	style := s.help
	if m.isError {
		style = s.danger
	}
	return s.footer.Width(width).Render(style.Render(message))
}

type styles struct {
	brand, brandSub, header, stats, stat, label, value    lipgloss.Style
	panelTitle, muted, empty, requestKind, active, danger lipgloss.Style
	help, footer, modal, modalTitle                       lipgloss.Style
	surface, border, selected, text                       color.Color
}

func newStyles(dark bool) styles {
	bg := lipgloss.Color("#0A0D12")
	surface := lipgloss.Color("#121821")
	border := lipgloss.Color("#283343")
	selected := lipgloss.Color("#1A2430")
	text := lipgloss.Color("#E8EDF5")
	muted := lipgloss.Color("#778397")
	acid := lipgloss.Color("#B9FF66")
	purple := lipgloss.Color("#9B87FF")
	red := lipgloss.Color("#FF6685")
	if !dark {
		bg, surface, border, selected = lipgloss.Color("#F5F7FA"), lipgloss.Color("#FFFFFF"), lipgloss.Color("#C9D1DC"), lipgloss.Color("#E8EEF5")
		text, muted, acid, purple, red = lipgloss.Color("#17202C"), lipgloss.Color("#637083"), lipgloss.Color("#3E7A00"), lipgloss.Color("#644ED0"), lipgloss.Color("#C92F52")
	}
	return styles{
		brand:       lipgloss.NewStyle().Bold(true).Foreground(acid),
		brandSub:    lipgloss.NewStyle().Bold(true).Foreground(text),
		header:      lipgloss.NewStyle().Background(bg).Padding(1, 2),
		stats:       lipgloss.NewStyle().Background(surface).Foreground(text).Padding(1, 2),
		stat:        lipgloss.NewStyle().Bold(true).Foreground(acid),
		label:       lipgloss.NewStyle().Bold(true).Foreground(muted),
		value:       lipgloss.NewStyle().Foreground(text),
		panelTitle:  lipgloss.NewStyle().Bold(true).Foreground(purple),
		muted:       lipgloss.NewStyle().Foreground(muted),
		empty:       lipgloss.NewStyle().Foreground(acid),
		requestKind: lipgloss.NewStyle().Bold(true).Foreground(purple),
		active:      lipgloss.NewStyle().Bold(true).Foreground(acid),
		danger:      lipgloss.NewStyle().Bold(true).Foreground(red),
		help:        lipgloss.NewStyle().Foreground(muted),
		footer:      lipgloss.NewStyle().Background(bg).Padding(1, 2),
		modal:       lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(purple).Background(surface).Foreground(text).Padding(1, 2),
		modalTitle:  lipgloss.NewStyle().Bold(true).Foreground(acid),
		surface:     surface, border: border, selected: selected, text: text,
	}
}

func (s styles) panel(focused bool, width int) lipgloss.Style {
	color := s.border
	if focused {
		color = lipgloss.Color("#9B87FF")
	}
	return lipgloss.NewStyle().Width(max(20, width-2)).Height(14).Border(lipgloss.RoundedBorder()).
		BorderForeground(color).Background(s.surface).Padding(1, 2)
}
func (s styles) row(selected bool) lipgloss.Style {
	style := lipgloss.NewStyle().Foreground(s.text).Padding(0, 1).MarginBottom(1)
	if selected {
		style = style.Background(s.selected).Bold(true)
	}
	return style
}

func shortID(value string) string {
	if len(value) <= 13 {
		return value
	}
	return value[:9] + "…" + value[len(value)-3:]
}
func trimMiddle(value string, width int) string {
	if width <= 0 || len(value) <= width {
		return value
	}
	left := (width - 1) / 2
	right := width - left - 1
	return value[:left] + "…" + value[len(value)-right:]
}
func humanTTL(ttl time.Duration) string {
	if ttl <= 0 {
		return "expired"
	}
	if ttl < time.Minute {
		return fmt.Sprintf("%ds", int(ttl.Seconds()))
	}
	if ttl < time.Hour {
		return fmt.Sprintf("%dm", int(ttl.Minutes()))
	}
	return fmt.Sprintf("%dh%02dm", int(ttl.Hours()), int(ttl.Minutes())%60)
}
func safeError(err error) string {
	value := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	if len(value) > 180 {
		return value[:180]
	}
	return value
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
