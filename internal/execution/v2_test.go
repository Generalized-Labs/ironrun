//go:build !windows

package execution

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
)

type v2MemoryStore struct{ values map[string]string }

func (s *v2MemoryStore) Name() string { return "memory" }
func (s *v2MemoryStore) Set(scope, key, value string) error {
	s.values[scope+"/"+key] = value
	return nil
}
func (s *v2MemoryStore) Get(scope, key string) (string, error) {
	value, ok := s.values[scope+"/"+key]
	if !ok {
		return "", envset.ErrMissing
	}
	return value, nil
}
func (s *v2MemoryStore) Delete(scope, key string) error { delete(s.values, scope+"/"+key); return nil }
func (s *v2MemoryStore) DeleteScope(scope string) error { return nil }

func TestV2DirectEntryExecutesAndRedacts(t *testing.T) {
	root := t.TempDir()
	store := &v2MemoryStore{values: map[string]string{}}
	manager := &envset.Manager{Root: root, Store: store, Now: time.Now, Meta: envset.Metadata{Version: 2, Active: "dev", Identity: envset.Identity{CanonicalPath: root}, Sets: map[string]envset.Set{"dev": {Name: "dev", CreatedAt: time.Now()}}}}
	value := "sk-" + strings.Repeat("v2dummy", 6)
	if err := manager.Put("dev", "OPENROUTER_API_KEY", value); err != nil {
		t.Fatal(err)
	}
	original := openEnvironment
	t.Cleanup(func() { openEnvironment = original })
	openEnvironment = func(string) (*envset.Manager, error) { return manager, nil }
	f := &policy.File{Version: policy.SupportedVersionV2, EnvironmentSet: "active", Commands: []policy.Command{{ID: "show", Argv: []string{"printenv", "OPENROUTER_API_KEY"}, Secrets: []string{"OPENROUTER_API_KEY"}}}}
	var stdout, stderr bytes.Buffer
	result, err := Run(context.Background(), f, "ironrun.yml", root, "show", Options{Environment: "dev", Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{result.Stdout, stdout.String(), stderr.String()} {
		if strings.Contains(output, value) {
			t.Fatal("v2 execution exposed direct environment value")
		}
	}
	if !strings.Contains(result.Stdout, "[REDACTED]") {
		t.Fatalf("v2 output was not redacted: %q", result.Stdout)
	}
}

func TestTrustedWorkspaceExecutesArbitraryArgvAndRedacts(t *testing.T) {
	root := t.TempDir()
	store := &v2MemoryStore{values: map[string]string{}}
	manager := &envset.Manager{Root: root, Store: store, Now: time.Now, Meta: envset.Metadata{Version: 2, Active: "dev", Identity: envset.Identity{CanonicalPath: root}, Sets: map[string]envset.Set{"dev": {Name: "dev", CreatedAt: time.Now()}}}}
	value := "sk-" + strings.Repeat("trusted-dummy", 5)
	if err := manager.Put("dev", "OPENROUTER_API_KEY", value); err != nil {
		t.Fatal(err)
	}
	original := openEnvironment
	t.Cleanup(func() { openEnvironment = original })
	openEnvironment = func(string) (*envset.Manager, error) { return manager, nil }
	var stdout, stderr bytes.Buffer
	result, err := RunWorkspace(context.Background(), root, "dev", []string{"printenv", "OPENROUTER_API_KEY"}, Options{Stdout: &stdout, Stderr: &stderr, SessionID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{result.Stdout, stdout.String(), stderr.String()} {
		if strings.Contains(output, value) {
			t.Fatal("trusted workspace output exposed a value")
		}
	}
	if !strings.Contains(result.Stdout, "[REDACTED]") {
		t.Fatalf("trusted workspace output was not redacted: %q", result.Stdout)
	}
}
