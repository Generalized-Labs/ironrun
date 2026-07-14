// Package tui provides Ironrun's value-blind terminal control room. It renders
// secret names and state but never reads values except inside a masked input
// that is immediately committed to the encrypted store.
package tui

import (
	"errors"
	"fmt"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/pending"
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
	modeEnableVault
	modeCreateEnvironment
	modeSecretKey
	modeDirectSecret
	modeImportSelect
	modeImportConfirm
	modeFileKey
	modeFilePath
	modePalette
	modeApproveCommand
)

type page int

const (
	pageWorkspace page = iota
	pageRun
	pageAccess
	pageAudit
)

var workspaceActions = []string{
	"Add secret", "Import .env", "Add secret file", "Run command", "New environment", "Grant agent access",
}

type Model struct {
	root       string
	policyPath string
	policy     *policy.File
	access     *access.Manager
	env        *envset.Manager

	environments   []envset.Set
	requests       []access.Request
	leases         []access.Lease
	focus          int
	cursor         [3]int
	page           page
	workspaceFocus int
	entryCursor    int
	actionCursor   int
	commandCursor  int
	proposals      []pending.Proposal
	mode           mode
	input          textinput.Model
	width          int
	height         int
	dark           bool
	message        string
	isError        bool
	pendingKey     string
	pendingImport  []envset.DotenvEntry
	importSelected map[int]bool
	temporaryEnv   bool
	showHelp       bool
	dotenvDetected bool
}

type refreshMsg struct{}
type runFinishedMsg struct{ err error }
type actionFinishedMsg struct {
	message string
	err     error
}

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
		input: input, dark: true, workspaceFocus: 2, importSelected: map[int]bool{},
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
	case runFinishedMsg:
		if msg.err != nil {
			m.refreshWithMessage("Command failed: "+safeError(msg.err), true)
		} else {
			m.refreshWithMessage("Sealed command completed", false)
		}
		return m, nil
	case actionFinishedMsg:
		if msg.err != nil {
			m.refreshWithMessage("Action failed: "+safeError(msg.err), true)
		} else {
			m.refreshWithMessage(msg.message, false)
		}
		return m, nil
	case tea.KeyPressMsg:
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		if m.mode == modeImportSelect {
			return m.updateImportSelection(msg)
		}
		if m.mode == modeSecret || m.mode == modeDirectSecret {
			return m.updateSecretInput(msg)
		}
		if m.mode == modeCreateEnvironment || m.mode == modeSecretKey || m.mode == modeFileKey || m.mode == modeFilePath || m.mode == modePalette {
			return m.updateTextInput(msg)
		}
		if m.mode != modeNormal {
			return m.updateConfirmation(msg)
		}
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "?":
			m.showHelp = true
		case "/":
			m.beginPalette()
		case "tab":
			m.page = (m.page + 1) % 4
		case "shift+tab":
			m.page = (m.page + 3) % 4
		case "right", "l":
			if m.page == pageWorkspace {
				m.workspaceFocus = (m.workspaceFocus + 1) % 3
			} else {
				m.focus = (m.focus + 1) % 3
			}
		case "left", "h":
			if m.page == pageWorkspace {
				m.workspaceFocus = (m.workspaceFocus + 2) % 3
			} else {
				m.focus = (m.focus + 2) % 3
			}
		case "up", "k":
			m.moveCursor(-1)
		case "down", "j":
			m.moveCursor(1)
		case "u":
			m.useSelectedEnvironment()
		case "e":
			if m.env == nil {
				m.mode = modeEnableVault
				m.message = "Enable the encrypted local vault and create environment dev?"
				m.isError = false
			}
		case "n":
			m.beginCreateEnvironment(false)
		case "t":
			m.beginCreateEnvironment(true)
		case "s":
			m.beginDirectSecret()
		case "a", "enter":
			return m, m.beginPageAction()
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
		m.resetInput("Secret entry cancelled")
		return m, nil
	case "enter":
		value := m.input.Value()
		m.input.SetValue("")
		m.input.Blur()
		if value == "" {
			m.message, m.isError = "Secret value cannot be empty", true
			return m, nil
		}
		var err error
		message := "Secret stored locally; MCP received no plaintext"
		if m.mode == modeDirectSecret {
			active, activeErr := m.env.Active()
			if activeErr != nil {
				err = activeErr
			} else {
				err = m.env.Put(active.Name, m.pendingKey, value)
				message = m.pendingKey + " stored in " + active.Name
			}
		} else {
			err = m.storeSecret(m.selectedRequest(), value)
		}
		value = "" // release the last local reference promptly
		m.pendingKey = ""
		m.mode = modeNormal
		if err != nil {
			m.message, m.isError = "Could not fulfill request: "+safeError(err), true
			return m, nil
		}
		m.refreshWithMessage(message, false)
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) updateTextInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.resetInput("Action cancelled")
		return m, nil
	case "enter":
		value := strings.TrimSpace(m.input.Value())
		if value == "" {
			m.message, m.isError = "A name is required", true
			return m, nil
		}
		if m.mode == modePalette {
			m.resetInput("")
			m.runPaletteAction(value)
			return m, nil
		}
		if m.mode == modeFileKey {
			if !validEnvironmentKey(value) {
				m.message, m.isError = "Use a target variable such as GOOGLE_APPLICATION_CREDENTIALS", true
				return m, nil
			}
			m.pendingKey = value
			m.mode = modeFilePath
			m.message = "Choose the local secret file to encrypt"
			m.input.Reset()
			m.input.Placeholder = "/path/to/service-account.json"
			_ = m.input.Focus()
			return m, nil
		}
		if m.mode == modeFilePath {
			key := m.pendingKey
			if err := m.storeFileSecret(value); err != nil {
				m.message, m.isError = safeError(err), true
				return m, nil
			}
			m.resetInput("")
			m.refreshWithMessage(key+" file encrypted; source file was not deleted", false)
			return m, nil
		}
		if m.mode == modeSecretKey {
			if !validEnvironmentKey(value) {
				m.message, m.isError = "Use an environment key such as OPENAI_API_KEY", true
				return m, nil
			}
			m.pendingKey = value
			m.mode = modeDirectSecret
			m.message = "Enter " + value + " locally"
			m.input.Reset()
			m.input.Placeholder = "secret value"
			m.input.EchoMode = textinput.EchoPassword
			_ = m.input.Focus()
			return m, nil
		}
		_, err := m.env.Create(value, m.temporaryEnv, envset.DefaultTTL)
		if err == nil {
			err = m.env.Use(value)
		}
		m.resetInput("")
		if err != nil {
			m.message, m.isError = safeError(err), true
		} else {
			m.refreshWithMessage("Created and activated environment "+value, false)
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) updateImportSelection(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc":
		m.pendingImport = nil
		m.mode = modeNormal
		m.message = "Import cancelled"
	case "up", "k":
		if m.entryCursor > 0 {
			m.entryCursor--
		}
	case "down", "j":
		if m.entryCursor+1 < len(m.pendingImport) {
			m.entryCursor++
		}
	case "space":
		m.importSelected[m.entryCursor] = !m.importSelected[m.entryCursor]
	case "enter":
		count := 0
		for i := range m.pendingImport {
			if m.importSelected[i] {
				count++
			}
		}
		if count == 0 {
			m.message, m.isError = "Select at least one key", true
			return m, nil
		}
		m.mode = modeImportConfirm
		m.message = fmt.Sprintf("Encrypt %d selected key(s) into the active environment?", count)
	}
	return m, nil
}

func (m *Model) updateConfirmation(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "esc", "n":
		m.mode = modeNormal
		m.message = "Action cancelled"
		return m, nil
	case "y", "enter":
		var err error
		completedMode := m.mode
		if completedMode == modeApproveCommand {
			proposal := m.selectedProposal()
			m.mode = modeNormal
			command := exec.Command(os.Args[0], "--policy", m.policyPath, "approve", proposal.ID, "--yes")
			command.Dir = m.root
			return m, tea.ExecProcess(command, func(err error) tea.Msg {
				return actionFinishedMsg{message: "Approved command " + proposal.ID, err: err}
			})
		}
		switch completedMode {
		case modeApprove:
			_, err = m.access.ApproveLease(m.selectedRequest().ID, 0)
		case modeDeny:
			err = m.access.Deny(m.selectedRequest().ID)
		case modeRevoke:
			err = m.access.Revoke(m.selectedLease().ID, "")
		case modeEnableVault:
			err = m.enableLocalVault()
		case modeImportConfirm:
			err = m.commitDotenvImport()
		}
		m.mode = modeNormal
		if err != nil {
			m.message, m.isError = safeError(err), true
		} else {
			message := "Access state updated"
			if completedMode == modeImportConfirm {
				message = m.message
			} else if completedMode == modeEnableVault {
				message = "Encrypted workspace enabled"
			}
			m.refreshWithMessage(message, false)
		}
	}
	return m, nil
}

func (m *Model) beginPalette() {
	m.mode = modePalette
	m.message = "Type an action: add, import, file, run, environment, access"
	m.input.Reset()
	m.input.Placeholder = "add secret"
	m.input.EchoMode = textinput.EchoNormal
	_ = m.input.Focus()
}

func (m *Model) runPaletteAction(value string) {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "import"):
		m.beginDotenvImport()
	case strings.Contains(value, "file"):
		m.beginFileSecret()
	case strings.Contains(value, "run"):
		m.page = pageRun
	case strings.Contains(value, "environment") || strings.Contains(value, "new"):
		m.beginCreateEnvironment(false)
	case strings.Contains(value, "access") || strings.Contains(value, "agent"):
		m.page = pageAccess
	default:
		m.beginDirectSecret()
	}
}

func (m *Model) beginDotenvImport() {
	if m.env == nil {
		m.message, m.isError = "Enable the encrypted vault first", true
		return
	}
	path := filepath.Join(m.root, ".env")
	entries, err := envset.ParseDotenv(path, "")
	if err != nil {
		m.message, m.isError = "Cannot import .env: "+safeError(err), true
		return
	}
	m.pendingImport = entries
	m.importSelected = map[int]bool{}
	for i := range entries {
		m.importSelected[i] = true
	}
	m.entryCursor = 0
	m.mode = modeImportSelect
	m.message = "Select key names to encrypt; values are never rendered"
}

func (m *Model) commitDotenvImport() error {
	active, err := m.env.Active()
	if err != nil {
		return err
	}
	for i, entry := range m.pendingImport {
		if !m.importSelected[i] {
			continue
		}
		if existing, ok := m.env.Entry(active.Name, entry.Key); ok {
			if existing.Kind != envset.EntryEnvironment {
				return fmt.Errorf("%s already exists as a file secret", entry.Key)
			}
			current, getErr := m.env.Get(active.Name, entry.Key)
			if getErr != nil {
				return fmt.Errorf("verify existing %s: %w", entry.Key, getErr)
			}
			if current == entry.Value {
				continue // safe retry after an interrupted import
			}
			return fmt.Errorf("%s is already configured; replace it separately", entry.Key)
		}
		if err := m.env.Put(active.Name, entry.Key, entry.Value); err != nil {
			return err
		}
		stored, err := m.env.Get(active.Name, entry.Key)
		if err != nil || stored != entry.Value {
			return fmt.Errorf("encrypted storage verification failed for %s", entry.Key)
		}
	}
	for i := range m.pendingImport {
		m.pendingImport[i].Value = ""
	}
	m.pendingImport = nil
	m.importSelected = map[int]bool{}
	m.message = "Import verified in encrypted storage. The plaintext .env still exists; remove or protect it when safe."
	return nil
}

func (m *Model) beginFileSecret() {
	if m.env == nil {
		m.message, m.isError = "Enable the encrypted vault first", true
		return
	}
	m.mode = modeFileKey
	m.message = "Name the environment variable that will receive the temporary file path"
	m.input.Reset()
	m.input.Placeholder = "GOOGLE_APPLICATION_CREDENTIALS"
	m.input.EchoMode = textinput.EchoNormal
	_ = m.input.Focus()
}

func (m *Model) storeFileSecret(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("file secret source must be a regular file, not a symlink")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("file secret permissions must be owner-only; run chmod 600 on the source")
	}
	if info.Size() > 16*1024*1024 {
		return errors.New("file secret exceeds the 16 MiB limit")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	active, err := m.env.Active()
	if err != nil {
		return err
	}
	name := m.pendingKey
	return m.env.PutEntry(active.Name, envset.Entry{Name: name, Kind: envset.EntryFile, Target: name, Filename: filepath.Base(path)}, value)
}

func (m *Model) beginCreateEnvironment(temporary bool) {
	if m.env == nil {
		m.message, m.isError = "Press e to enable the encrypted local vault first", true
		return
	}
	m.mode = modeCreateEnvironment
	m.temporaryEnv = temporary
	m.message = "Name the new project environment"
	if temporary {
		m.message = "Name the new 24-hour session environment"
	}
	m.input.Reset()
	m.input.Placeholder = "dev, staging, agent-session"
	m.input.EchoMode = textinput.EchoNormal
	_ = m.input.Focus()
}

func (m *Model) beginDirectSecret() {
	if m.env == nil {
		m.message, m.isError = "Press e to enable the encrypted local vault first", true
		return
	}
	if _, err := m.env.Active(); err != nil {
		m.message, m.isError = "Create or select an environment first", true
		return
	}
	m.mode = modeSecretKey
	m.message = "Enter the environment key to store"
	m.input.Reset()
	m.input.Placeholder = "OPENAI_API_KEY"
	m.input.EchoMode = textinput.EchoNormal
	_ = m.input.Focus()
}

func (m *Model) resetInput(message string) {
	m.input.SetValue("")
	m.input.Blur()
	m.input.EchoMode = textinput.EchoPassword
	m.pendingKey = ""
	m.temporaryEnv = false
	m.mode = modeNormal
	m.message = message
}

func (m *Model) enableLocalVault() error {
	data, err := os.ReadFile(m.policyPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "environment_set:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "environment_set: active"
			found = true
		}
	}
	if !found {
		lines = append(lines, "environment_set: active")
	}
	info, err := os.Stat(m.policyPath)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(m.policyPath), ".ironrun-policy-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.WriteString(strings.Join(lines, "\n")); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, m.policyPath); err != nil {
		return err
	}
	m.policy, err = policy.Load(m.policyPath)
	if err != nil {
		return err
	}
	m.env, err = envset.Open(m.root)
	if err != nil {
		return err
	}
	set, err := m.env.Ensure("dev")
	if err != nil {
		return err
	}
	if err := m.env.Use(set.Name); err != nil {
		return err
	}
	dir := filepath.Join(m.root, ".ironrun")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	ignore := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(ignore); os.IsNotExist(err) {
		if err := os.WriteFile(ignore, []byte("*\n!.gitignore\n"), 0600); err != nil {
			return err
		}
	}
	return m.reload()
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

func (m *Model) moveCursor(delta int) {
	move := func(cursor *int, limit int) {
		if limit == 0 {
			*cursor = 0
			return
		}
		*cursor = max(0, min(limit-1, *cursor+delta))
	}
	switch m.page {
	case pageWorkspace:
		switch m.workspaceFocus {
		case 0:
			move(&m.cursor[focusEnvironments], len(m.environments))
		case 1:
			entries := m.activeEntries()
			move(&m.entryCursor, len(entries))
		case 2:
			move(&m.actionCursor, len(workspaceActions))
		}
	case pageRun:
		move(&m.commandCursor, len(m.policy.Commands)+len(m.proposals))
	case pageAccess:
		move(&m.cursor[m.focus], m.focusLength(m.focus))
	}
}

func (m *Model) beginPageAction() tea.Cmd {
	switch m.page {
	case pageWorkspace:
		if m.workspaceFocus == 0 {
			m.useSelectedEnvironment()
			return nil
		}
		if m.workspaceFocus == 2 {
			m.runWorkspaceAction(m.actionCursor)
		}
	case pageRun:
		if m.commandCursor < len(m.policy.Commands) {
			id := m.policy.Commands[m.commandCursor].ID
			m.message = "Running sealed command " + id + "…"
			command := exec.Command(os.Args[0], "--policy", m.policyPath, "exec", id)
			command.Dir = m.root
			return tea.ExecProcess(command, func(err error) tea.Msg { return runFinishedMsg{err: err} })
		} else if len(m.proposals) > 0 {
			proposal := m.selectedProposal()
			m.mode = modeApproveCommand
			m.message = "Approve exact argv for " + proposal.ID + " and save it to policy?"
		}
	case pageAccess:
		m.beginPrimaryAction()
	}
	return nil
}

func (m *Model) runWorkspaceAction(index int) {
	switch index {
	case 0:
		m.beginDirectSecret()
	case 1:
		m.beginDotenvImport()
	case 2:
		m.beginFileSecret()
	case 3:
		m.page = pageRun
	case 4:
		m.beginCreateEnvironment(false)
	case 5:
		m.page = pageAccess
		m.message = "Approve a pending agent request to issue a revocable lease"
	}
}

func (m *Model) activeEntries() []envset.Entry {
	if m.env == nil || m.env.Meta.Active == "" {
		return nil
	}
	set, ok := m.env.Set(m.env.Meta.Active)
	if !ok {
		return nil
	}
	return set.Entries
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
	loadedPolicy, err := policy.Load(m.policyPath)
	if err != nil {
		return err
	}
	m.policy = loadedPolicy
	pendingStore, err := pending.Load(pending.Path(m.policyPath))
	if err != nil {
		return err
	}
	m.proposals = append(m.proposals[:0], pendingStore.Proposals...)
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
	if info, statErr := os.Lstat(filepath.Join(m.root, ".env")); statErr == nil {
		m.dotenvDetected = info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
	} else {
		m.dotenvDetected = false
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

func (m *Model) selectedProposal() pending.Proposal {
	index := m.commandCursor - len(m.policy.Commands)
	if index < 0 || index >= len(m.proposals) {
		return pending.Proposal{}
	}
	return m.proposals[index]
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
	footer := m.renderFooter(styles, width)
	panelHeight := 14
	if m.height > 0 {
		minimumPanelHeight := 5
		if m.page == pageWorkspace && m.mode == modeNormal && !m.showHelp {
			minimumPanelHeight = 12
		}
		panelHeight = m.height - lipgloss.Height(header) - lipgloss.Height(stats) - lipgloss.Height(footer)
		if panelHeight < minimumPanelHeight {
			// The action bar is the dashboard's discoverability and control
			// surface. Prefer it over secondary stats in short embedded terminals.
			stats = ""
			panelHeight = m.height - lipgloss.Height(header) - lipgloss.Height(footer)
		}
		if panelHeight < minimumPanelHeight {
			// Input and approval modals need more room than the brand header.
			header = ""
			panelHeight = m.height - lipgloss.Height(footer)
		}
		panelHeight = max(3, panelHeight)
	}
	panels := m.renderPanels(styles, width, panelHeight)
	blocks := make([]string, 0, 4)
	if header != "" {
		blocks = append(blocks, header)
	}
	if stats != "" {
		blocks = append(blocks, stats)
	}
	blocks = append(blocks, panels, footer)
	content := lipgloss.JoinVertical(lipgloss.Left, blocks...)
	view := tea.NewView(content)
	view.AltScreen = true
	return view
}

func (m *Model) renderHeader(s styles, width int) string {
	brand := s.brand.Render("IRONRUN") + " " + s.brandSub.Render("ENCRYPTED WORKSPACE")
	identity := m.root
	if m.env != nil && m.env.Meta.Identity.RemoteURL != "" {
		identity = m.env.Meta.Identity.RemoteURL
	}
	right := s.muted.Render(trimMiddle(identity, max(20, width-lipgloss.Width(brand)-8)))
	gap := max(1, width-lipgloss.Width(brand)-lipgloss.Width(right)-4)
	tabs := []string{"Workspace", "Run", "Agent Access", "Audit"}
	for i := range tabs {
		if page(i) == m.page {
			tabs[i] = s.active.Render("[" + tabs[i] + "]")
		}
	}
	return s.header.Width(width).Render(brand + strings.Repeat(" ", gap) + right + "\n  " + strings.Join(tabs, "   "))
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

func (m *Model) renderPanels(s styles, width, height int) string {
	switch m.page {
	case pageWorkspace:
		return m.renderWorkspace(s, width, height)
	case pageRun:
		return m.renderRun(s, width, height)
	case pageAudit:
		return s.renderPanel(true, width, height, s.panelTitle.Render("AUDIT & SECURITY")+"\n\nTamper-evident execution records stay value-blind.\n\nUse `ironrun audit` to inspect and verify the chain.")
	case pageAccess:
		if width >= 86 {
			left := width / 2
			return lipgloss.JoinHorizontal(lipgloss.Top, m.renderRequests(s, left, height), m.renderLeases(s, width-left, height))
		}
	}
	if width < 86 {
		panelHeight := max(3, height/3)
		return lipgloss.JoinVertical(lipgloss.Left,
			m.renderEnvironments(s, width, panelHeight), m.renderRequests(s, width, panelHeight), m.renderLeases(s, width, panelHeight))
	}
	inner := width - 4
	left := max(24, inner*27/100)
	middle := max(32, inner*38/100)
	right := max(28, inner-left-middle)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		m.renderEnvironments(s, left, height), m.renderRequests(s, middle, height), m.renderLeases(s, right, height))
}

func (m *Model) renderWorkspace(s styles, width, height int) string {
	if width < 86 {
		switch m.workspaceFocus {
		case 0:
			return m.renderEnvironments(s, width, height)
		case 1:
			return m.renderEntries(s, width, height)
		default:
			return m.renderActions(s, width, height)
		}
	}
	left := max(24, width*24/100)
	middle := max(34, width*42/100)
	right := max(28, width-left-middle)
	return lipgloss.JoinHorizontal(lipgloss.Top, m.renderEnvironments(s, left, height), m.renderEntries(s, middle, height), m.renderActions(s, right, height))
}

func (m *Model) renderEntries(s styles, width, height int) string {
	entries := m.activeEntries()
	rows := []string{}
	if len(entries) == 0 {
		rows = append(rows, s.empty.Render("No secrets yet\nChoose Add secret or Import .env →"))
	}
	for i, entry := range entries {
		kind := "ENV"
		detail := "configured · never revealable"
		if entry.Kind == envset.EntryFile {
			kind, detail = "FILE", entry.Filename+" · encrypted"
		}
		row := fmt.Sprintf("● %s\n  %s · %s", entry.Name, kind, detail)
		rows = append(rows, s.row(m.workspaceFocus == 1 && i == m.entryCursor).Render(row))
	}
	content := s.panelTitle.Render("SECRETS · "+strings.ToUpper(m.activeEnvironmentName())) + "\n\n" + strings.Join(rows, "\n")
	return s.renderPanel(m.workspaceFocus == 1, width, height, content)
}

func (m *Model) renderActions(s styles, width, height int) string {
	rows := make([]string, 0, len(workspaceActions))
	for i, action := range workspaceActions {
		if i == 1 && m.dotenvDetected {
			action += "  · detected"
		}
		marker := "  "
		if m.workspaceFocus == 2 && i == m.actionCursor {
			marker = "› "
		}
		row := s.row(m.workspaceFocus == 2 && i == m.actionCursor)
		if height < 18 {
			row = row.MarginBottom(0)
		}
		rows = append(rows, row.Render(marker+action))
	}
	return s.renderPanel(m.workspaceFocus == 2, width, height, s.panelTitle.Render("ACTIONS")+"\n\n"+strings.Join(rows, "\n"))
}

func (m *Model) renderRun(s styles, width, height int) string {
	rows := []string{}
	for i, command := range m.policy.Commands {
		secrets := "no workspace secrets"
		if len(command.Secrets) > 0 {
			secrets = strings.Join(command.Secrets, ", ")
		}
		row := fmt.Sprintf("%s\n  argv: %q\n  secrets: %s · workdir: %s\n  timeout: %s · network: %s · output: %s", command.ID, command.Argv, secrets, commandWorkDir(command), commandTimeout(command), commandNetwork(command), commandOutputLimit(command))
		rows = append(rows, s.row(i == m.commandCursor).Render(row))
	}
	if len(m.proposals) > 0 {
		rows = append(rows, "", s.panelTitle.Render("REVIEW QUEUE · ENTER TO APPROVE"))
		for i, proposal := range m.proposals {
			secrets := "none"
			if len(proposal.Env) > 0 {
				names := make([]string, 0, len(proposal.Env))
				for name := range proposal.Env {
					names = append(names, name)
				}
				sort.Strings(names)
				secrets = strings.Join(names, ", ")
			}
			row := fmt.Sprintf("%s\n  argv: %q\n  workdir: project · secrets: %s\n  timeout: 120s · network: allowed · output: unlimited\n  reason: %s", proposal.ID, proposal.Argv, secrets, proposal.Reason)
			rows = append(rows, s.row(len(m.policy.Commands)+i == m.commandCursor).Render(row))
		}
	}
	return s.renderPanel(true, width, height, s.panelTitle.Render("APPROVED COMMANDS · ENTER TO RUN")+"\n\n"+strings.Join(rows, "\n"))
}

func commandWorkDir(command policy.Command) string {
	if command.WorkDir == "" {
		return "project"
	}
	return command.WorkDir
}

func commandTimeout(command policy.Command) string {
	if command.TTL.Duration == 0 {
		return "unlimited"
	}
	return command.TTL.Duration.String()
}

func commandNetwork(command policy.Command) string {
	if command.NoNetwork {
		return "blocked"
	}
	return "allowed"
}

func commandOutputLimit(command policy.Command) string {
	if command.MaxBytes == 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d bytes", command.MaxBytes)
}

func (m *Model) activeEnvironmentName() string {
	if m.env != nil && m.env.Meta.Active != "" {
		return m.env.Meta.Active
	}
	return "default"
}

func (m *Model) renderEnvironments(s styles, width, height int) string {
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
		focused := (m.page == pageWorkspace && m.workspaceFocus == 0) || (m.page != pageWorkspace && m.focus == focusEnvironments)
		rows = append(rows, s.row(focused && i == m.cursor[focusEnvironments]).Render(row))
	}
	content := s.panelTitle.Render("01  ENVIRONMENTS") + "\n\n" + strings.Join(rows, "\n")
	focused := (m.page == pageWorkspace && m.workspaceFocus == 0) || (m.page != pageWorkspace && m.focus == focusEnvironments)
	return s.renderPanel(focused, width, height, content)
}

func (m *Model) renderRequests(s styles, width, height int) string {
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
	content := s.panelTitle.Render("02  AGENT INBOX") + "\n\n" + strings.Join(rows, "\n")
	return s.renderPanel(m.focus == focusRequests, width, height, content)
}

func (m *Model) renderLeases(s styles, width, height int) string {
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
	content := s.panelTitle.Render("03  LIVE LEASES") + "\n\n" + strings.Join(rows, "\n")
	return s.renderPanel(m.focus == focusLeases, width, height, content)
}

func (m *Model) renderFooter(s styles, width int) string {
	if m.showHelp {
		box := s.modal.Width(max(30, min(76, width-6))).Render(s.modalTitle.Render("IRONRUN HELP") + "\n\n↑↓ select  ·  ←→ choose pane  ·  enter open\ntab next screen  ·  / command palette  ·  esc back  ·  q quit\n\nValues can be replaced or injected, never revealed or copied.")
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, box)
	}
	if m.mode == modeImportSelect {
		rows := []string{}
		for i, entry := range m.pendingImport {
			mark := "[ ]"
			if m.importSelected[i] {
				mark = "[x]"
			}
			cursor := "  "
			if i == m.entryCursor {
				cursor = "› "
			}
			rows = append(rows, cursor+mark+" "+entry.Key)
		}
		box := s.modal.Width(max(30, min(70, width-6))).Render(s.modalTitle.Render("IMPORT .ENV") + "\n" + s.muted.Render("Key names only; values remain hidden") + "\n\n" + strings.Join(rows, "\n") + "\n\n" + s.help.Render("space toggle · enter review · esc cancel"))
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, box)
	}
	if m.mode == modeSecret || m.mode == modeDirectSecret {
		box := s.modal.Width(max(30, min(66, width-6))).Render(
			s.modalTitle.Render("SEALED INPUT") + "\n" + s.muted.Render(m.message) + "\n\n" + m.input.View() +
				"\n\n" + s.help.Render("enter store locally  ·  esc cancel  ·  value never rendered"))
		return lipgloss.PlaceHorizontal(width, lipgloss.Center, box)
	}
	if m.mode == modeCreateEnvironment || m.mode == modeSecretKey || m.mode == modeFileKey || m.mode == modeFilePath || m.mode == modePalette {
		box := s.modal.Width(max(30, min(66, width-6))).Render(
			s.modalTitle.Render("LOCAL VAULT SETUP") + "\n" + s.muted.Render(m.message) + "\n\n" + m.input.View() +
				"\n\n" + s.help.Render("enter continue  ·  esc cancel"))
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
		if m.env == nil {
			message = "e enable encrypted vault  ·  tab move  ·  enter act  ·  g refresh  ·  q quit"
		} else {
			message = "↑↓ select  ·  ←→ pane  ·  enter open  ·  tab screen  ·  / actions  ·  ? help  ·  q quit"
		}
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

func (s styles) renderPanel(focused bool, width, height int, content string) string {
	// Clip the body before drawing the frame so short terminals retain a
	// complete border instead of cutting off its bottom edge.
	innerHeight := max(1, height-4) // two border rows plus vertical padding
	content = lipgloss.NewStyle().MaxHeight(innerHeight).Render(content)
	return s.panel(focused, width, height).Render(content)
}

func (s styles) panel(focused bool, width, height int) lipgloss.Style {
	color := s.border
	if focused {
		color = lipgloss.Color("#9B87FF")
	}
	return lipgloss.NewStyle().Width(max(20, width-2)).Height(height).Border(lipgloss.RoundedBorder()).
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
func validEnvironmentKey(value string) bool {
	if value == "" || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_') {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
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
