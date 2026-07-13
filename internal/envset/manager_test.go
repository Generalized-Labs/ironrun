package envset

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeStore struct{ values map[string]string }

func (f *fakeStore) Name() string { return "fake" }
func (f *fakeStore) Set(scope, key, value string) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[scope+"/"+key] = value
	return nil
}
func (f *fakeStore) Get(scope, key string) (string, error) {
	v, ok := f.values[scope+"/"+key]
	if !ok {
		return "", ErrMissing
	}
	return v, nil
}
func (f *fakeStore) Delete(scope, key string) error { delete(f.values, scope+"/"+key); return nil }
func (f *fakeStore) DeleteScope(scope string) error {
	for key := range f.values {
		if strings.HasPrefix(key, scope+"/") {
			delete(f.values, key)
		}
	}
	return nil
}

func testManager(t *testing.T) (*Manager, *fakeStore) {
	t.Helper()
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	return &Manager{Root: t.TempDir(), Store: store, Now: func() time.Time { return now }, Meta: Metadata{Version: metadataVersion, Identity: Identity{RemoteURL: "https://github.com/acme/app", CanonicalPath: "/tmp/app"}, Sets: map[string]Set{}}}, store
}

func TestManagerLifecycleAndExpiry(t *testing.T) {
	m, store := testManager(t)
	if _, err := m.Create("dev", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Put("dev", "API_KEY", "secret-value"); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Get("dev", "API_KEY"); err != nil || got != "secret-value" {
		t.Fatalf("get = %q, %v", got, err)
	}
	if err := m.Clone("dev", "staging"); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Get("staging", "API_KEY"); err != nil || got != "secret-value" {
		t.Fatalf("clone get = %q, %v", got, err)
	}
	if err := m.DeleteKey("staging", "API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get("staging", "API_KEY"); !errors.Is(err, ErrMissing) {
		t.Fatalf("expected missing after delete, got %v", err)
	}
	if len(store.values) != 1 {
		t.Fatalf("expected only source value, got %d", len(store.values))
	}
}

func TestTemporarySetExpiresAndPrunes(t *testing.T) {
	m, _ := testManager(t)
	if _, err := m.Create("session", true, time.Hour); err != nil {
		t.Fatal(err)
	}
	s, _ := m.Set("session")
	expired := s.ExpiresAt.Add(time.Second)
	m.Now = func() time.Time { return expired }
	if _, err := m.Get("session", "KEY"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
	removed, err := m.Prune()
	if err != nil || removed != 1 {
		t.Fatalf("prune = %d, %v", removed, err)
	}
}

func TestParseDotenvRejectsUnsafeAndDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(path, []byte("A=one\nA=two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDotenv(path, ""); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDotenv(path, ""); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permission error, got %v", err)
	}
}

func TestParseDotenvQuotedAndMultiline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.env")
	data := "# comment\nAPI_KEY=abc\nMESSAGE=\"hello\\nworld\"\nMULTI=\"first\nsecond\"\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseDotenv(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[1].Value != "hello\nworld" || entries[2].Value != "first\nsecond" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestTemplateNeverContainsValues(t *testing.T) {
	m, _ := testManager(t)
	if _, err := m.Create("dev", false, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Put("dev", "API_KEY", "do-not-export"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "template.env")
	if err := m.Template("dev", path, []string{"API_KEY"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "API_KEY=\n" {
		t.Fatalf("template = %q", data)
	}
	if strings.Contains(string(data), "do-not-export") {
		t.Fatal("template leaked value")
	}
}

func TestNormalizeRemote(t *testing.T) {
	if got := normalizeRemote("git@GitHub.com:Acme/App.git"); got != "ssh://git@github.com/Acme/App" {
		t.Fatalf("normalized SSH remote = %q", got)
	}
	if got := normalizeRemote("HTTPS://GitHub.com/Acme/App.git/"); got != "https://github.com/Acme/App" {
		t.Fatalf("normalized HTTPS remote = %q", got)
	}
}
