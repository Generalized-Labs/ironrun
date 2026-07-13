package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

func TestFileStoreRoundTripRotateDelete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store, err := Open(filepath.Join(home, "project", "ironrun.yml"), "envfile")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("API_KEY", "super-secret-value"); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got != "super-secret-value" {
		t.Fatalf("got %q", got)
	}
	path := filepath.Join(home, ".ironrun", "secrets")
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one policy store, got %d", len(entries))
	}
	if err := store.Delete("API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("API_KEY"); err != ErrMissing {
		t.Fatalf("expected ErrMissing, got %v", err)
	}
}

func TestFileStoreDoesNotPersistPlaintext(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	store, err := Open(filepath.Join(home, "ironrun.yml"), "envfile")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("TOKEN", "plaintext-must-not-be-on-disk"); err != nil {
		t.Fatal(err)
	}
	var found []byte
	_ = filepath.Walk(home, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && !info.IsDir() {
			b, _ := os.ReadFile(path)
			found = append(found, b...)
		}
		return nil
	})
	if string(found) == "" {
		t.Fatal("expected store files")
	}
	if string(found) != "" && contains(found, []byte("plaintext-must-not-be-on-disk")) {
		t.Fatal("plaintext secret persisted")
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

type mapStore struct {
	name   string
	values map[string]string
}

func (s *mapStore) Name() string                 { return s.name }
func (s *mapStore) Set(name, value string) error { s.values[name] = value; return nil }
func (s *mapStore) Get(name string) (string, error) {
	value, ok := s.values[name]
	if !ok {
		return "", ErrMissing
	}
	return value, nil
}
func (s *mapStore) Delete(name string) error { delete(s.values, name); return nil }

func TestResolveAliasesWithOpenerSupportsMixedStores(t *testing.T) {
	f, err := policy.Parse([]byte(`version: "1"
provider: env
secrets:
  keychain_key:
    env: KEYCHAIN_KEY
    store: keychain
    allow: [deploy]
  file_key:
    env: FILE_KEY
    store: envfile
    allow: [deploy]
commands:
  - id: deploy
    argv: [echo, deploy]
    secrets: [keychain_key, file_key]
`))
	if err != nil {
		t.Fatal(err)
	}
	keychain := &mapStore{name: "keychain", values: map[string]string{"keychain_key": "one"}}
	envfile := &mapStore{name: "envfile", values: map[string]string{"file_key": "two"}}
	opened := map[string]int{}
	resolved, err := ResolveAliasesWithOpener(f, &f.Commands[0], func(requested string) (Store, error) {
		opened[requested]++
		switch requested {
		case "keychain":
			return keychain, nil
		case "envfile":
			return envfile, nil
		default:
			return nil, errors.New("unexpected store")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved["KEYCHAIN_KEY"] != "one" || resolved["FILE_KEY"] != "two" {
		t.Fatalf("resolved = %#v", resolved)
	}
	if opened["keychain"] != 1 || opened["envfile"] != 1 {
		t.Fatalf("opened = %#v", opened)
	}
}
