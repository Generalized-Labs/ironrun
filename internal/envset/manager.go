package envset

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const metadataVersion = 1
const DefaultTTL = 24 * time.Hour

type Identity struct {
	RemoteURL     string `json:"remote_url"`
	CanonicalPath string `json:"canonical_path"`
}
type Set struct {
	Name      string     `json:"name"`
	Temporary bool       `json:"temporary"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Keys      []string   `json:"keys,omitempty"`
}
type Metadata struct {
	Version  int            `json:"version"`
	Identity Identity       `json:"identity"`
	Active   string         `json:"active,omitempty"`
	Sets     map[string]Set `json:"sets"`
}
type Manager struct {
	Root  string
	Meta  Metadata
	Store ValueStore
	Now   func() time.Time
}

func Open(root string) (*Manager, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	identity, err := DiscoverIdentity(root)
	if err != nil {
		return nil, err
	}
	store, err := OpenVault(identity)
	if err != nil {
		return nil, err
	}
	m := &Manager{Root: root, Store: store, Now: time.Now}
	path := metadataPath(root)
	if data, readErr := os.ReadFile(path); readErr == nil {
		if err := json.Unmarshal(data, &m.Meta); err != nil {
			return nil, fmt.Errorf("parse environment metadata: %w", err)
		}
		if m.Meta.Version != metadataVersion {
			return nil, fmt.Errorf("unsupported environment metadata version %d", m.Meta.Version)
		}
		if m.Meta.Sets == nil {
			m.Meta.Sets = map[string]Set{}
		}
		if m.Meta.Identity != identity {
			return nil, errors.New("project identity changed; run `ironrun env init` to inspect or migrate")
		}
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	} else {
		m.Meta = Metadata{Version: metadataVersion, Identity: identity, Sets: map[string]Set{}}
	}
	return m, nil
}

func DiscoverIdentity(root string) (Identity, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Identity{}, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Identity{}, err
	}
	out, gitErr := exec.Command("git", "-C", root, "remote", "get-url", "origin").Output()
	remote := ""
	if gitErr == nil {
		remote = normalizeRemote(string(out))
	}
	return Identity{RemoteURL: remote, CanonicalPath: filepath.Clean(root)}, nil
}

func normalizeRemote(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "git@") {
		raw = "ssh://" + strings.Replace(raw, ":", "/", 1)
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimRight(u.Path, "/")
		u.Path = strings.TrimSuffix(u.Path, ".git")
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	return strings.TrimSuffix(strings.TrimRight(raw, "/"), ".git")
}

func (m *Manager) Save() error {
	if err := os.MkdirAll(filepath.Join(m.Root, ".ironrun"), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.Meta, "", "  ")
	if err != nil {
		return err
	}
	path := metadataPath(m.Root)
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func metadataPath(root string) string          { return filepath.Join(root, ".ironrun", "environments.json") }
func MetadataExists(root string) bool          { _, err := os.Stat(metadataPath(root)); return err == nil }
func (m *Manager) Set(name string) (Set, bool) { s, ok := m.Meta.Sets[name]; return s, ok }
func (m *Manager) Create(name string, temporary bool, ttl time.Duration) (Set, error) {
	if err := validateName(name); err != nil {
		return Set{}, err
	}
	if _, ok := m.Meta.Sets[name]; ok {
		return Set{}, fmt.Errorf("environment set %q already exists", name)
	}
	if temporary && ttl <= 0 {
		ttl = DefaultTTL
	}
	now := m.Now()
	s := Set{Name: name, Temporary: temporary, CreatedAt: now}
	if temporary {
		expires := now.Add(ttl)
		s.ExpiresAt = &expires
	}
	m.Meta.Sets[name] = s
	if m.Meta.Active == "" {
		m.Meta.Active = name
	}
	return s, m.Save()
}
func (m *Manager) Ensure(name string) (Set, error) {
	if s, ok := m.Set(name); ok {
		return s, nil
	}
	return m.Create(name, false, 0)
}
func (m *Manager) Use(name string) error {
	if _, ok := m.Set(name); !ok {
		return fmt.Errorf("environment set %q not found", name)
	}
	m.Meta.Active = name
	return m.Save()
}
func (m *Manager) Active() (Set, error) {
	if m.Meta.Active == "" {
		return Set{}, errors.New("no active environment set")
	}
	s, ok := m.Set(m.Meta.Active)
	if !ok {
		return Set{}, errors.New("active environment set is missing")
	}
	if m.Expired(s) {
		return Set{}, fmt.Errorf("environment set %q has expired", s.Name)
	}
	return s, nil
}
func (m *Manager) Expired(s Set) bool { return s.ExpiresAt != nil && !m.Now().Before(*s.ExpiresAt) }
func (m *Manager) Put(setName, key, value string) error {
	s, ok := m.Set(setName)
	if !ok {
		return fmt.Errorf("environment set %q not found", setName)
	}
	if m.Expired(s) {
		return fmt.Errorf("environment set %q has expired", setName)
	}
	if err := m.Store.Set(m.scope(setName), key, value); err != nil {
		return err
	}
	if !contains(s.Keys, key) {
		s.Keys = append(s.Keys, key)
		sort.Strings(s.Keys)
		m.Meta.Sets[setName] = s
		return m.Save()
	}
	return nil
}
func (m *Manager) Get(setName, key string) (string, error) {
	s, ok := m.Set(setName)
	if !ok {
		return "", fmt.Errorf("environment set %q not found", setName)
	}
	if m.Expired(s) {
		return "", fmt.Errorf("environment set %q has expired", setName)
	}
	return m.Store.Get(m.scope(setName), key)
}
func (m *Manager) DeleteKey(setName, key string) error {
	s, ok := m.Set(setName)
	if !ok {
		return fmt.Errorf("environment set %q not found", setName)
	}
	if err := m.Store.Delete(m.scope(setName), key); err != nil {
		return err
	}
	s.Keys = remove(s.Keys, key)
	m.Meta.Sets[setName] = s
	return m.Save()
}
func (m *Manager) Remove(setName string) error {
	s, ok := m.Set(setName)
	if !ok {
		return fmt.Errorf("environment set %q not found", setName)
	}
	for _, key := range s.Keys {
		if err := m.Store.Delete(m.scope(setName), key); err != nil && !errors.Is(err, ErrMissing) {
			return err
		}
	}
	delete(m.Meta.Sets, setName)
	if m.Meta.Active == setName {
		m.Meta.Active = ""
		names := m.Names()
		if len(names) > 0 {
			m.Meta.Active = names[0]
		}
	}
	return m.Save()
}
func (m *Manager) Clone(from, to string) error {
	src, ok := m.Set(from)
	if !ok {
		return fmt.Errorf("environment set %q not found", from)
	}
	if _, ok := m.Set(to); ok {
		return fmt.Errorf("environment set %q already exists", to)
	}
	if _, err := m.Create(to, false, 0); err != nil {
		return err
	}
	for _, key := range src.Keys {
		value, err := m.Get(from, key)
		if err != nil {
			return err
		}
		if err := m.Put(to, key, value); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) Prune() (int, error) {
	removed := 0
	for name, s := range m.Meta.Sets {
		if s.Temporary && m.Expired(s) {
			if err := m.Remove(name); err != nil {
				return removed, err
			}
			removed++
		}
	}
	return removed, nil
}
func (m *Manager) Names() []string {
	out := make([]string, 0, len(m.Meta.Sets))
	for name := range m.Meta.Sets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
func (m *Manager) scope(set string) string { return identityHash(m.Meta.Identity) + "/" + set }
func identityHash(i Identity) string {
	h := sha256.Sum256([]byte(i.RemoteURL + "\x00" + i.CanonicalPath))
	return fmt.Sprintf("%x", h[:])
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func remove(values []string, want string) []string {
	out := values[:0]
	for _, v := range values {
		if v != want {
			out = append(out, v)
		}
	}
	return out
}

type DotenvEntry struct{ Key, Value string }

func ParseDotenv(path, projectRoot string) ([]DotenvEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("refusing env file %q: permissions must be owner-only", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, _ := filepath.Abs(projectRoot)
	if projectRoot != "" && strings.HasPrefix(abs, filepath.Clean(root)+string(os.PathSeparator)) {
		return nil, fmt.Errorf("refusing env file inside project; pass an explicit unsafe override")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var entries []DotenvEntry
	seen := map[string]bool{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed env line")
		}
		key = strings.TrimSpace(key)
		if err := validateName(key); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate env key %q", key)
		}
		seen[key] = true
		value = strings.TrimSpace(value)
		if len(value) > 0 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] != value[0] {
			quote := value[0]
			for value[len(value)-1] != quote && scanner.Scan() {
				value += "\n" + scanner.Text()
			}
			if len(value) == 0 || value[len(value)-1] != quote {
				return nil, fmt.Errorf("unterminated quoted value for %q", key)
			}
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		entries = append(entries, DotenvEntry{Key: key, Value: strings.ReplaceAll(value, "\\n", "\n")})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
func (m *Manager) Template(setName, path string, keys []string) error {
	if _, ok := m.Set(setName); !ok {
		return fmt.Errorf("environment set %q not found", setName)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
