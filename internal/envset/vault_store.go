package envset

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/generalized-labs/ironrun/internal/vault"
)

// OpenVault returns the encrypted project store. A protector wraps only the
// project root key; values themselves always live in the encrypted vault. When
// the OS credential manager is the protector it also remains a read-through
// migration source for values created by older Ironrun versions.
func OpenVault(identity Identity) (ValueStore, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(ProtectorEnv)))

	dir, err := vault.DefaultDir()
	if err != nil {
		return nil, err
	}
	projectID := identityHash(identity)

	switch mode {
	case "", "auto", "native", "keychain":
		native, err := OpenNative()
		if err != nil {
			return nil, headlessHint(err)
		}
		sealed, err := vault.Open(dir, projectID, nativeProtector{store: native})
		if err != nil {
			// A credential manager that exists but cannot be used — a cancelled
			// Keychain prompt, a locked keyring — fails here rather than above.
			if mode == "" || mode == "auto" {
				return nil, headlessHint(err)
			}
			return nil, fmt.Errorf("open encrypted project vault: %w", err)
		}
		return &migratingVaultStore{vault: sealed, legacy: native, protector: native.Name()}, nil

	case "file":
		protector, err := newFileProtector()
		if err != nil {
			return nil, fmt.Errorf("open vault key file: %w", err)
		}
		sealed, err := vault.Open(dir, projectID, protector)
		if err != nil {
			return nil, fmt.Errorf("open encrypted project vault: %w", err)
		}
		return &migratingVaultStore{vault: sealed, legacy: noLegacyStore{}, protector: protector.Name()}, nil

	default:
		return nil, fmt.Errorf("unknown %s value %q (use auto or file)", ProtectorEnv, mode)
	}
}

// headlessHint explains the credential-manager requirement and the opt-in
// alternatives. Ironrun never downgrades the protector on its own, so this is
// the only place a user learns the vault has a headless mode.
func headlessHint(cause error) error {
	return fmt.Errorf(`open encrypted project vault: %w

Ironrun wraps the vault root key with your OS credential manager, which needs an
interactive desktop session. This looks like a headless environment (SSH without
a session, a container, or a CI runner).

Choose one:
  • Run Ironrun from a desktop session.
  • Opt in to an owner-only key file:
        export %s=file
    The root key is written to ~/.ironrun/%s/<id>.key with 0600 permissions.
    This is weaker than the OS credential manager: any process running as your
    user can read it, with no prompt.
  • For CI, a version-1 policy with "provider: env" redacts command output
    without using the vault at all`, cause, ProtectorEnv, keyFileDirName)
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
	vault     *vault.Store
	legacy    ValueStore
	protector string
}

func (s *migratingVaultStore) Name() string {
	return "Ironrun encrypted vault (root key in " + s.protector + ")"
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
