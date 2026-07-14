package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type memoryProtector struct{ values map[string]string }

func (m *memoryProtector) Load(name string) (string, error) {
	value, ok := m.values[name]
	if !ok {
		return "", ErrKeyMissing
	}
	return value, nil
}
func (m *memoryProtector) Save(name, value string) error {
	m.values[name] = value
	return nil
}

func testStore(t *testing.T) (*Store, *memoryProtector) {
	t.Helper()
	p := &memoryProtector{values: map[string]string{}}
	s, err := Open(t.TempDir(), "github.com/acme/app", p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestStoreRoundTripRotationAndNoPlaintextAtRest(t *testing.T) {
	s, _ := testStore(t)
	if err := s.Set("dev", "OPENAI_API_KEY", "sk-secret-first"); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first, []byte("OPENAI_API_KEY")) || bytes.Contains(first, []byte("sk-secret-first")) {
		t.Fatalf("vault contains plaintext: %s", first)
	}
	if err := s.Set("dev", "OPENAI_API_KEY", "sk-secret-second"); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("scope rewrite did not rotate ciphertext")
	}
	got, err := s.Get("dev", "OPENAI_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk-secret-second" {
		t.Fatalf("value = %q", got)
	}
	if info, err := os.Stat(s.Path()); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("vault permissions = %o", info.Mode().Perm())
	}
}

func TestStoreOpaqueBytesNeverAppearAtRest(t *testing.T) {
	s, _ := testStore(t)
	value := []byte{0, 1, 2, 3, 255, 's', 'e', 'c', 'r', 'e', 't'}
	if err := s.SetBytes("dev", "CERT_FILE", value); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, value) || bytes.Contains(data, []byte("CERT_FILE")) {
		t.Fatal("vault exposed blob or name")
	}
	got, err := s.GetBytes("dev", "CERT_FILE")
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("blob = %v, %v", got, err)
	}
}

func TestStoreScopesDeleteIndependently(t *testing.T) {
	s, _ := testStore(t)
	for _, tc := range []struct{ scope, key, value string }{
		{"dev", "TOKEN", "dev-token"},
		{"prod", "TOKEN", "prod-token"},
	} {
		if err := s.Set(tc.scope, tc.key, tc.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteScope("dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("dev", "TOKEN"); !errors.Is(err, ErrMissing) {
		t.Fatalf("deleted scope error = %v", err)
	}
	if got, err := s.Get("prod", "TOKEN"); err != nil || got != "prod-token" {
		t.Fatalf("prod value = %q, %v", got, err)
	}
	if err := s.Delete("prod", "TOKEN"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("prod", "TOKEN"); !errors.Is(err, ErrMissing) {
		t.Fatalf("deleted value error = %v", err)
	}
}

func TestStoreTamperWrongKeyAndWrongProjectFailClosed(t *testing.T) {
	s, _ := testStore(t)
	if err := s.Set("dev", "TOKEN", "secret"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["revision"] = float64(99)
	tampered, _ := json.Marshal(doc)
	if err := os.WriteFile(s.Path(), tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("dev", "TOKEN"); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered vault error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "vault.irvault")
	key := bytes.Repeat([]byte{1}, 32)
	good, err := OpenWithKey(path, "project-a", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := good.Set("dev", "TOKEN", "secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithKey(path, "project-a", bytes.Repeat([]byte{2}, 32)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong key error = %v", err)
	}
	if _, err := OpenWithKey(path, "project-b", key); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong project error = %v", err)
	}
}

func TestOpenDoesNotReplaceMissingKeyForExistingVault(t *testing.T) {
	dir := t.TempDir()
	p := &memoryProtector{values: map[string]string{}}
	s, err := Open(dir, "project", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("dev", "TOKEN", "secret"); err != nil {
		t.Fatal(err)
	}
	for key := range p.values {
		delete(p.values, key)
	}
	_, err = Open(dir, "project", p)
	if !errors.Is(err, ErrKeyMissing) || !strings.Contains(err.Error(), "encrypted vault exists") {
		t.Fatalf("missing protected key error = %v", err)
	}
}
