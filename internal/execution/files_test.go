package execution

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileWorkspacePermissionsCleanupAndTraversal(t *testing.T) {
	base := t.TempDir()
	dir, err := os.MkdirTemp(base, "run-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	w := &fileWorkspace{dir: dir}
	path, err := w.Materialize("credential.json", []byte("secret-file-value"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, %v", info.Mode().Perm(), err)
	}
	if _, err := w.Materialize("../escape", []byte("no")); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("materialized file survived cleanup: %v", err)
	}
}

func TestCleanupStaleFileWorkspaces(t *testing.T) {
	base := t.TempDir()
	old := filepath.Join(base, "run-old")
	fresh := filepath.Join(base, "run-fresh")
	for _, path := range []string{old, fresh} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(old, now.Add(-25*time.Hour), now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleFileWorkspaces(base, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("stale workspace not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh workspace removed")
	}
}

func TestConcurrentFileWorkspacesAreIsolated(t *testing.T) {
	first, err := newFileWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := newFileWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	firstPath, err := first.Materialize("same.json", []byte("first-secret"))
	if err != nil {
		t.Fatal(err)
	}
	secondPath, err := second.Materialize("same.json", []byte("second-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(firstPath) == filepath.Dir(secondPath) {
		t.Fatal("concurrent executions shared a runtime directory")
	}
}
