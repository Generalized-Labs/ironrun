package envset

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInspectMetadataReadOnlyCompatibility(t *testing.T) {
	root := t.TempDir()
	identity, err := DiscoverIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	// Keys from an old set migrate in memory. A partially populated Entries
	// slice remains authoritative, just as in the runtime's migration.
	meta := Metadata{Version: 1, Identity: identity, Active: "dev", Sets: map[string]Set{
		"dev":     {Name: "dev", Keys: []string{"TOKEN"}},
		"partial": {Name: "partial", Keys: []string{"STALE"}, Entries: []Entry{{Name: "CURRENT", Kind: EntryEnvironment, Target: "CURRENT"}}},
	}}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	path := metadataPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectMetadata(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || len(got.Sets["dev"].Entries) != 1 || got.Sets["dev"].Entries[0].Name != "TOKEN" {
		t.Fatalf("v1 keys were not interpreted: %+v", got)
	}
	if !reflect.DeepEqual(got.Sets["partial"].Entries, meta.Sets["partial"].Entries) {
		t.Fatal("stale keys were merged into existing entries")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(data) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("inspection changed metadata")
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 1 {
		t.Fatalf("inspection created state: files=%v err=%v", files, err)
	}
}

func TestInspectMetadataRejectsUnavailableConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name              string
		data              string
		wantIdentityError bool
	}{
		{name: "absent"},
		{name: "corrupt", data: "{"},
		{name: "unsupported", data: `{"version": 99}`},
		{name: "other project", data: `{"version": 2, "identity": {"canonical_path": "/another-project"}}`, wantIdentityError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.data != "" {
				if err := os.Mkdir(filepath.Join(root, ".ironrun"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(metadataPath(root), []byte(tc.data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := InspectMetadata(root)
			if err == nil {
				t.Fatal("inspection accepted unavailable configuration")
			}
			if tc.wantIdentityError && !errors.Is(err, ErrProjectIdentityChanged) {
				t.Fatalf("expected identity error: %v", err)
			}
			if tc.data == "" {
				if _, err := os.Stat(filepath.Join(root, ".ironrun")); !os.IsNotExist(err) {
					t.Fatal("inspection created local state")
				}
			}
		})
	}
}
