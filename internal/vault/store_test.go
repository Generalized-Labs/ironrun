package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestReplaceRefusesForeignOlderAndConflictingDocuments(t *testing.T) {
	key := bytes.Repeat([]byte{7}, rootKeySize)
	open := func(projectID string, key []byte) *Store {
		t.Helper()
		s, err := OpenWithKey(filepath.Join(t.TempDir(), "p.irvault"), projectID, key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	snapshot := func(s *Store) []byte {
		t.Helper()
		data, err := os.ReadFile(s.Path())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	remote := open("project", key)
	_ = remote.Set("dev", "TOKEN", "first")
	older := snapshot(remote)
	_ = remote.Set("dev", "TOKEN", "second")
	newer := snapshot(remote)

	local := open("project", key)
	if err := local.Replace(older); err != nil {
		t.Fatalf("authentic document refused: %v", err)
	}
	if err := local.Replace(older); err != nil {
		t.Fatalf("identical document refused: %v", err)
	}
	conflicting := open("project", key)
	_ = conflicting.Set("dev", "TOKEN", "diverged")
	foreign := open("project", bytes.Repeat([]byte{9}, rootKeySize))
	otherProject := open("other", key)
	for i := 0; i < 5; i++ {
		_ = foreign.Set("dev", "TOKEN", "foreign")
		_ = otherProject.Set("dev", "TOKEN", "other")
	}
	before := snapshot(local)
	for name, data := range map[string][]byte{
		"conflicting same revision": snapshot(conflicting),
		"different root key":        snapshot(foreign),
		"different project":         snapshot(otherProject),
		"not a vault":               []byte("<html>not found</html>"),
	} {
		if err := local.Replace(data); err == nil {
			t.Fatalf("%s: replace succeeded", name)
		}
		if !bytes.Equal(snapshot(local), before) {
			t.Fatalf("%s: local vault changed after refusal", name)
		}
	}

	if err := local.Replace(newer); err != nil {
		t.Fatalf("authentic newer document refused: %v", err)
	}
	if err := local.Replace(older); err == nil {
		t.Fatal("older revision replaced the local vault")
	}
	if got, err := local.Get("dev", "TOKEN"); err != nil || got != "second" {
		t.Fatalf("value = %q, %v", got, err)
	}
}

// initializationProtector makes concurrent missing-key reads observable while
// holding the first key-manager save. It never uses platform credentials.
type initializationProtector struct {
	mu               sync.Mutex
	value            string
	loads, saves     int
	firstSaveStarted chan struct{}
	releaseFirstSave chan struct{}
	secondLoad       chan struct{}
}

func (p *initializationProtector) Load(string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loads++
	if p.loads == 2 {
		close(p.secondLoad)
	}
	if p.value == "" {
		return "", ErrKeyMissing
	}
	return p.value, nil
}

func (p *initializationProtector) Save(_ string, value string) error {
	p.mu.Lock()
	p.saves++
	first := p.saves == 1
	p.mu.Unlock()
	if first {
		close(p.firstSaveStarted)
		<-p.releaseFirstSave
	}
	p.mu.Lock()
	p.value = value
	p.mu.Unlock()
	return nil
}

func TestOpenConcurrentInitializationKeepsPersistedKey(t *testing.T) {
	dir := t.TempDir()
	p := &initializationProtector{
		firstSaveStarted: make(chan struct{}),
		releaseFirstSave: make(chan struct{}),
		secondLoad:       make(chan struct{}),
	}
	type opened struct {
		store *Store
		err   error
	}
	results := make(chan opened, 2)
	open := func() {
		s, err := Open(dir, "concurrent-project", p)
		results <- opened{s, err}
	}
	go open()
	select {
	case <-p.firstSaveStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first Open did not reach key-manager save")
	}
	go open()
	// Before the fix the second Open reaches Load while the first Save is
	// pending, observes another missing key, and creates a different root key.
	// Correct initialization holds the OS lock until the key is persisted.
	select {
	case <-p.secondLoad:
	case <-time.After(100 * time.Millisecond):
	}
	close(p.releaseFirstSave)
	var stores []*Store
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("concurrent Open failed: %v", result.err)
			}
			stores = append(stores, result.store)
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent Open did not finish")
		}
	}
	if p.saves != 1 {
		t.Errorf("saved %d root keys; want one shared project key", p.saves)
	}
	for i, s := range stores {
		if err := s.Set("dev", []string{"ONE", "TWO"}[i], "synthetic-init-value"); err != nil {
			t.Fatalf("store %d cannot read the other's committed vault: %v", i, err)
		}
	}
	reopened, err := Open(dir, "concurrent-project", p)
	if err != nil {
		t.Fatalf("reopen with persisted key: %v", err)
	}
	for _, name := range []string{"ONE", "TWO"} {
		if value, err := reopened.Get("dev", name); err != nil || value != "synthetic-init-value" {
			t.Errorf("reopened %s = %q, %v", name, value, err)
		}
	}
}
