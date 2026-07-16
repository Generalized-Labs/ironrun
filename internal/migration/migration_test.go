package migration

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

type memoryValues struct{ values map[string]string }

func (m *memoryValues) Name() string { return "memory" }
func (m *memoryValues) Set(scope, key, value string) error {
	m.values[scope+"/"+key] = value
	return nil
}
func (m *memoryValues) Get(scope, key string) (string, error) {
	value, ok := m.values[scope+"/"+key]
	if !ok {
		return "", envset.ErrMissing
	}
	return value, nil
}
func (m *memoryValues) Delete(scope, key string) error { delete(m.values, scope+"/"+key); return nil }
func (m *memoryValues) DeleteScope(scope string) error {
	for key := range m.values {
		if strings.HasPrefix(key, scope+"/") {
			delete(m.values, key)
		}
	}
	return nil
}

type memoryLegacy struct{ values map[string]string }

func (m *memoryLegacy) Name() string                 { return "legacy" }
func (m *memoryLegacy) Set(name, value string) error { m.values[name] = value; return nil }
func (m *memoryLegacy) Get(name string) (string, error) {
	value, ok := m.values[name]
	if !ok {
		return "", secretstore.ErrMissing
	}
	return value, nil
}
func (m *memoryLegacy) Delete(name string) error { delete(m.values, name); return nil }

func TestApplyRollbackAndCleanupAreTransactional(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	legacyPolicy := `# keep this review comment
version: "1"
provider: passthrough
secrets:
  openrouter:
    env: OPENROUTER_API_KEY
    store: envfile
    allow: [benchmark]
commands:
  - id: benchmark
    argv: [printenv, OPENROUTER_API_KEY]
    secrets: [openrouter]
`
	if err := os.WriteFile(policyPath, []byte(legacyPolicy), 0600); err != nil {
		t.Fatal(err)
	}
	values := &memoryValues{values: map[string]string{}}
	manager := &envset.Manager{Root: root, Store: values, Now: time.Now, Meta: envset.Metadata{Version: 2, Identity: envset.Identity{CanonicalPath: root}, Sets: map[string]envset.Set{"dev": {Name: "dev", CreatedAt: time.Now()}}, Active: "dev"}}
	legacyValue := "sk-" + strings.Repeat("migration", 5)
	legacy := &memoryLegacy{values: map[string]string{"openrouter": legacyValue}}
	originalEnv, originalSecrets := openEnvironment, openSecretStore
	t.Cleanup(func() { openEnvironment, openSecretStore = originalEnv, originalSecrets })
	openEnvironment = func(string) (*envset.Manager, error) { return manager, nil }
	openSecretStore = func(string, string) (secretstore.Store, error) { return legacy, nil }

	manifest, err := Apply(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := policy.Load(policyPath)
	if err != nil || !f.UsesEnvironmentEntries() || f.Commands[0].Secrets[0] != "OPENROUTER_API_KEY" {
		t.Fatalf("migrated policy = %#v, %v", f, err)
	}
	stored, err := manager.Get("dev", "OPENROUTER_API_KEY")
	if err != nil || stored != legacyValue {
		t.Fatal("encrypted destination was not verified")
	}
	for _, path := range []string{policyPath, filepath.Join(root, ".ironrun", "migrations", manifest.ID, "manifest.json")} {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(data), legacyValue) {
			t.Fatalf("value leaked into %s", path)
		}
	}

	rolledBack, err := Rollback(policyPath, manifest.ID)
	if err != nil || rolledBack.Status != "rolled_back" {
		t.Fatalf("rollback = %#v, %v", rolledBack, err)
	}
	if _, err := manager.Get("dev", "OPENROUTER_API_KEY"); !errors.Is(err, envset.ErrMissing) {
		t.Fatalf("copied value survived rollback: %v", err)
	}
	if f, err := policy.Load(policyPath); err != nil || f.Version != policy.SupportedVersionV1 {
		t.Fatalf("restored policy = %#v, %v", f, err)
	}

	manifest, err = Apply(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, err := Cleanup(policyPath, manifest.ID)
	if err != nil || cleaned.Status != "cleaned" {
		t.Fatalf("cleanup = %#v, %v", cleaned, err)
	}
	if _, ok := legacy.values["openrouter"]; ok {
		t.Fatal("legacy alias survived confirmed cleanup")
	}
	if _, err := Rollback(policyPath, manifest.ID); err == nil {
		t.Fatal("cleanup should permanently end rollback")
	}
}
