package envset

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/generalized-labs/ironrun/internal/vault"
)

func TestMigratingVaultStoreMovesLegacyValueAfterCommit(t *testing.T) {
	legacy := &fakeStore{values: map[string]string{"scope/TOKEN": "legacy-secret"}}
	sealed, err := vault.OpenWithKey(filepath.Join(t.TempDir(), "vault.irvault"), "project", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &migratingVaultStore{vault: sealed, legacy: legacy}
	got, err := store.Get("scope", "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if got != "legacy-secret" {
		t.Fatalf("value = %q", got)
	}
	if _, ok := legacy.values["scope/TOKEN"]; ok {
		t.Fatal("legacy value was not removed after vault commit")
	}
	if got, err := sealed.Get("scope", "TOKEN"); err != nil || got != "legacy-secret" {
		t.Fatalf("vault value = %q, %v", got, err)
	}
}

func TestMigratingVaultStoreReturnsMissingWithoutDisclosure(t *testing.T) {
	legacy := &fakeStore{values: map[string]string{}}
	sealed, err := vault.OpenWithKey(filepath.Join(t.TempDir(), "vault.irvault"), "project", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := &migratingVaultStore{vault: sealed, legacy: legacy}
	if _, err := store.Get("scope", "TOKEN"); !errors.Is(err, ErrMissing) {
		t.Fatalf("error = %v", err)
	}
}
