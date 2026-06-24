package pending_test

import (
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
