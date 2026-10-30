package pending_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/generalized-labs/ironrun/internal/pending"
)

func TestStore_UpsertFindRemoveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ironrun", "pending.yml")

	st, err := pending.Load(path) // missing file -> empty store, no error
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Proposals) != 0 {
		t.Fatalf("expected empty store, got %d", len(st.Proposals))
	}

	st.Upsert(pending.Proposal{ID: "a", Argv: []string{"ls"}, Status: "pending"})
	st.Upsert(pending.Proposal{ID: "a", Argv: []string{"ls", "-la"}, Status: "pending"}) // replace, not dup
	if len(st.Proposals) != 1 {
		t.Errorf("upsert should replace by id, got %d", len(st.Proposals))
	}
	if p := st.Find("a"); p == nil || len(p.Argv) != 2 {
		t.Errorf("find returned wrong proposal: %+v", p)
	}

	if err := pending.Save(path, st); err != nil {
		t.Fatal(err)
	}
	st2, err := pending.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if st2.Find("a") == nil {
		t.Error("round-trip lost the proposal")
	}
	if _, ok := st2.Remove("a"); !ok {
		t.Error("remove should report the proposal existed")
	}
	if st2.Find("a") != nil {
		t.Error("proposal not removed")
	}
	if _, ok := st2.Remove("missing"); ok {
		t.Error("remove of a missing id should report false")
	}
}

func TestPath(t *testing.T) {
	got := pending.Path(filepath.Join("proj", "ironrun.yml"))
	want := filepath.Join("proj", ".ironrun", "pending.yml")
	if got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestCreatePreservesImmutableContentAndOriginalTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ironrun", "pending.yml")
	original := pending.Proposal{ID: "reviewed", Argv: []string{"echo", "original"}, Reason: "fixture", ProposedAt: "first", Status: "pending"}
	if _, err := pending.Create(path, original); err != nil {
		t.Fatal(err)
	}
	repeat := original
	repeat.ProposedAt = "later"
	got, err := pending.Create(path, repeat)
	if err != nil || got.ProposedAt != "first" {
		t.Fatalf("repeat = %#v, %v", got, err)
	}
	changed := original
	changed.Argv = []string{"echo", "changed"}
	if _, err := pending.Create(path, changed); !errors.Is(err, pending.ErrConflict) {
		t.Fatalf("conflicting creation = %v", err)
	}
	store, err := pending.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if pending.ReviewDigest(*store.Find("reviewed")) != pending.ReviewDigest(original) {
		t.Fatal("reviewed proposal changed")
	}
}

func TestConcurrentCreatesPreserveDifferentIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ironrun", "pending.yml")
	const callers = 20
	start := make(chan struct{})
	errors := make(chan error, callers)
	for i := range callers {
		go func() {
			<-start
			_, err := pending.Create(path, pending.Proposal{ID: fmt.Sprintf("id-%d", i), Argv: []string{"echo", "fixture"}, Status: "pending"})
			errors <- err
		}()
	}
	close(start)
	for range callers {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	store, err := pending.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Proposals) != callers {
		t.Fatalf("stored %d proposals; want %d", len(store.Proposals), callers)
	}
}
