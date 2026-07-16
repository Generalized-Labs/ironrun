package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Path: filepath.Join(t.TempDir(), "ironrun", "projects.json"), Now: func() time.Time {
		return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	}}
}

func TestRegisterPreservesStableID(t *testing.T) {
	s := testStore(t)
	root := t.TempDir()
	first, err := s.Register(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Register(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("project ID changed: %q -> %q", first.ID, second.ID)
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("registry permissions = %o", info.Mode().Perm())
	}
}

func TestRepairPreservesIDAndRejectsDuplicatePath(t *testing.T) {
	s := testStore(t)
	firstRoot, secondRoot, movedRoot := t.TempDir(), t.TempDir(), t.TempDir()
	first, _ := s.Register(firstRoot)
	second, _ := s.Register(secondRoot)
	repaired, err := s.Repair(first.ID, movedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.ID != first.ID || repaired.Path == first.Path {
		t.Fatalf("repair did not preserve identity: %#v", repaired)
	}
	if _, err := s.Repair(second.ID, movedRoot); err == nil {
		t.Fatal("expected duplicate path rejection")
	}
}

func TestResolveUniqueNameAndAmbiguousName(t *testing.T) {
	s := testStore(t)
	baseA, baseB := t.TempDir(), t.TempDir()
	one := filepath.Join(baseA, "app")
	two := filepath.Join(baseB, "app")
	if err := os.Mkdir(one, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(two, 0700); err != nil {
		t.Fatal(err)
	}
	p, _ := s.Register(one)
	if got, err := s.Resolve("app"); err != nil || got.ID != p.ID {
		t.Fatalf("resolve unique name = %#v, %v", got, err)
	}
	_, _ = s.Register(two)
	if _, err := s.Resolve("app"); err == nil {
		t.Fatal("expected ambiguous name error")
	}
}

func TestCorruptRegistryFailsClosed(t *testing.T) {
	s := testStore(t)
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path, []byte("{not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("expected corrupt registry error")
	}
}
