package envset

import (
	"errors"
	"fmt"

	"github.com/generalized-labs/ironrun/internal/vault"
)

// OpenVault returns the encrypted project store. The native credential manager
// protects only the project root key and remains a read-through migration
// source for values created by older Ironrun versions.
func OpenVault(identity Identity) (ValueStore, error) {
	native, err := OpenNative()
	if err != nil {
		return nil, err
	}
	dir, err := vault.DefaultDir()
	if err != nil {
		return nil, err
	}
	projectID := identityHash(identity)
	sealed, err := vault.Open(dir, projectID, nativeProtector{store: native})
	if err != nil {
		return nil, fmt.Errorf("open encrypted project vault: %w", err)
	}
	return &migratingVaultStore{vault: sealed, legacy: native}, nil
}

type nativeProtector struct{ store ValueStore }

func (p nativeProtector) Load(name string) (string, error) {
	value, err := p.store.Get("vault-keys", name)
	if errors.Is(err, ErrMissing) {
		return "", vault.ErrKeyMissing
	}
	return value, err
}
func (p nativeProtector) Save(name, encodedKey string) error {
	return p.store.Set("vault-keys", name, encodedKey)
}

type migratingVaultStore struct {
	vault  *vault.Store
	legacy ValueStore
}

func (s *migratingVaultStore) Name() string {
	return "Ironrun encrypted vault (root key in " + s.legacy.Name() + ")"
}

func (s *migratingVaultStore) ExportRootKey() string {
	return s.vault.ExportRootKey()
}

func (s *migratingVaultStore) VaultPath() string {
	return s.vault.Path()
}
func (s *migratingVaultStore) Set(scope, key, value string) error {
	return s.vault.Set(scope, key, value)
}
func (s *migratingVaultStore) SetBytes(scope, key string, value []byte) error {
	return s.vault.SetBytes(scope, key, value)
}
func (s *migratingVaultStore) Get(scope, key string) (string, error) {
	value, err := s.vault.Get(scope, key)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, vault.ErrMissing) {
		return "", err
	}

	// Read-through migration is ordered so interruption cannot lose the only
	// committed value: vault commit first, legacy delete second.
	value, err = s.legacy.Get(scope, key)
	if err != nil {
		return "", ErrMissing
	}
	if err := s.vault.Set(scope, key, value); err != nil {
		return "", fmt.Errorf("migrate environment value into vault: %w", err)
	}
	_ = s.legacy.Delete(scope, key) // duplicate ciphertext/credential is safer than data loss
	return value, nil
}
func (s *migratingVaultStore) GetBytes(scope, key string) ([]byte, error) {
	value, err := s.vault.GetBytes(scope, key)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, vault.ErrMissing) {
		return nil, err
	}
	legacy, err := s.legacy.Get(scope, key)
	if err != nil {
		return nil, ErrMissing
	}
	value = []byte(legacy)
	if err := s.vault.SetBytes(scope, key, value); err != nil {
		return nil, fmt.Errorf("migrate environment value into vault: %w", err)
	}
	_ = s.legacy.Delete(scope, key)
	return value, nil
}
func (s *migratingVaultStore) Delete(scope, key string) error {
	vaultErr := s.vault.Delete(scope, key)
	legacyErr := s.legacy.Delete(scope, key)
	if vaultErr != nil {
		return vaultErr
	}
	return legacyErr
}
func (s *migratingVaultStore) DeleteScope(scope string) error {
	if err := s.vault.DeleteScope(scope); err != nil {
		return err
	}
	return s.legacy.DeleteScope(scope)
}
