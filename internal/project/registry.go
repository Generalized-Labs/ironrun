// Package project manages Ironrun's value-blind global project registry.
package project

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const registryVersion = 1

var ErrNotFound = errors.New("project not found")

// Project is safe, value-blind metadata about one local checkout. ID is stable
// across path repairs and intentionally independent from the encrypted vault ID.
type Project struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	RemoteHint   string    `json:"remote_hint,omitempty"`
	Configured   bool      `json:"configured"`
	CreatedAt    time.Time `json:"created_at"`
	LastOpenedAt time.Time `json:"last_opened_at"`
}

type registry struct {
	Version  int       `json:"version"`
	Projects []Project `json:"projects"`
}

// Store serializes access to one owner-only registry file.
type Store struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func DefaultPath() (string, error) {
	if home := strings.TrimSpace(os.Getenv("IRONRUN_HOME")); home != "" {
		return filepath.Join(home, "projects.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate Ironrun home: %w", err)
	}
	return filepath.Join(home, ".ironrun", "projects.json"), nil
}

func DefaultStore() (*Store, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	return &Store{Path: path, Now: time.Now}, nil
}

func (s *Store) List() ([]Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load()
	if err != nil {
		return nil, err
	}
	projects := append([]Project(nil), r.Projects...)
	sort.Slice(projects, func(i, j int) bool {
		return projects[i].LastOpenedAt.After(projects[j].LastOpenedAt)
	})
	return projects, nil
}

// Register creates or refreshes a project for path. Re-registering the same
// canonical checkout preserves its stable project ID.
func (s *Store) Register(path string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	canonical, err := canonicalPath(path)
	if err != nil {
		return Project{}, err
	}
	r, err := s.load()
	if err != nil {
		return Project{}, err
	}
	now := s.now().UTC()
	for i := range r.Projects {
		if samePath(r.Projects[i].Path, canonical) {
			r.Projects[i].Name = projectName(canonical)
			r.Projects[i].RemoteHint = remoteHint(canonical)
			r.Projects[i].Configured = configured(canonical)
			r.Projects[i].LastOpenedAt = now
			if err := s.save(r); err != nil {
				return Project{}, err
			}
			return r.Projects[i], nil
		}
	}
	id, err := randomID()
	if err != nil {
		return Project{}, err
	}
	p := Project{ID: id, Name: projectName(canonical), Path: canonical, RemoteHint: remoteHint(canonical), Configured: configured(canonical), CreatedAt: now, LastOpenedAt: now}
	r.Projects = append(r.Projects, p)
	if err := s.save(r); err != nil {
		return Project{}, err
	}
	return p, nil
}

// Resolve matches a project by exact ID, unique ID prefix, name, or path.
func (s *Store) Resolve(query string) (Project, error) {
	projects, err := s.List()
	if err != nil {
		return Project{}, err
	}
	if query == "" {
		return Project{}, ErrNotFound
	}
	if abs, err := filepath.Abs(query); err == nil {
		for _, p := range projects {
			if samePath(p.Path, abs) {
				return p, nil
			}
		}
	}
	var matches []Project
	for _, p := range projects {
		if p.ID == query {
			return p, nil
		}
		if strings.HasPrefix(p.ID, query) || p.Name == query {
			matches = append(matches, p)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return Project{}, fmt.Errorf("project %q is ambiguous; use a path or longer ID", query)
	}
	return Project{}, fmt.Errorf("%w: %s", ErrNotFound, query)
}

// Repair changes a checkout path without changing its ID.
func (s *Store) Repair(id, newPath string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	canonical, err := canonicalPath(newPath)
	if err != nil {
		return Project{}, err
	}
	r, err := s.load()
	if err != nil {
		return Project{}, err
	}
	for _, p := range r.Projects {
		if p.ID != id && samePath(p.Path, canonical) {
			return Project{}, fmt.Errorf("path is already registered to project %s", p.ID)
		}
	}
	for i := range r.Projects {
		if r.Projects[i].ID == id {
			r.Projects[i].Path = canonical
			r.Projects[i].Name = projectName(canonical)
			r.Projects[i].RemoteHint = remoteHint(canonical)
			r.Projects[i].Configured = configured(canonical)
			r.Projects[i].LastOpenedAt = s.now().UTC()
			if err := s.save(r); err != nil {
				return Project{}, err
			}
			return r.Projects[i], nil
		}
	}
	return Project{}, fmt.Errorf("%w: %s", ErrNotFound, id)
}

func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load()
	if err != nil {
		return err
	}
	for i := range r.Projects {
		if r.Projects[i].ID == id {
			r.Projects = append(r.Projects[:i], r.Projects[i+1:]...)
			return s.save(r)
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, id)
}

func (s *Store) load() (registry, error) {
	r := registry{Version: registryVersion, Projects: []Project{}}
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return registry{}, fmt.Errorf("read project registry: %w", err)
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return registry{}, fmt.Errorf("project registry is corrupt at %s: %w", s.Path, err)
	}
	if r.Version != registryVersion {
		return registry{}, fmt.Errorf("unsupported project registry version %d", r.Version)
	}
	return r, nil
}

func (s *Store) save(r registry) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create Ironrun home: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure Ironrun home: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".projects-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return err
	}
	return os.Chmod(s.Path, 0600)
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("open project %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("project path %q is not a directory", path)
	}
	return filepath.Clean(resolved), nil
}

func remoteHint(path string) string {
	out, err := exec.Command("git", "-C", path, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func configured(path string) bool {
	if _, err := os.Stat(filepath.Join(path, "ironrun.yml")); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(path, ".ironrun", "environments.json"))
	return err == nil
}

func projectName(path string) string { return filepath.Base(filepath.Clean(path)) }
func samePath(a, b string) bool      { return filepath.Clean(a) == filepath.Clean(b) }

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate project id: %w", err)
	}
	// RFC 4122 variant and version bits make IDs familiar without adding a
	// dependency or tying identity to a path, remote, or secret material.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(b)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
