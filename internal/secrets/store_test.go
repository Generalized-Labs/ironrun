package secrets

import (
	"os"
	"path/filepath"
	"testing"
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
