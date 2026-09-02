package envset

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/generalized-labs/ironrun/internal/vault"
)

// ProtectorEnv selects how the project vault root key is wrapped.
//
// Unset or "auto" uses the operating system credential manager, which needs an
// interactive desktop session. "file" opts in to an owner-only key file so the
// vault works in a headless environment — a container, a plain SSH session, or
// a Linux host without libsecret. The downgrade is never automatic: a headless
// session gets an error explaining the choice rather than a silently weaker
// vault.
const ProtectorEnv = "IRONRUN_VAULT_PROTECTOR"

// keyFileDirName is the owner-only directory holding wrapped root keys.
const keyFileDirName = "keys"

// fileProtector wraps the project vault root key in an owner-only file.
//
// This is deliberately weaker than an OS credential manager: the key is
// readable by any process running as the same user, with no per-application
// access control and no OS prompt on read. It exists so headless environments
// can use the encrypted vault at all. Ironrun's threat model already excludes a
// hostile process running as the same user (see SECURITY.md), so this protector
// does not weaken the agent boundary Ironrun is built to defend — an agent
// still never receives a value through any tool.
type fileProtector struct{ dir string }

func newFileProtector() (fileProtector, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return fileProtector{}, fmt.Errorf("locate home directory: %w", err)
	}
	dir := filepath.Join(home, ".ironrun", keyFileDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fileProtector{}, fmt.Errorf("create vault key directory: %w", err)
	}
	// MkdirAll is a no-op on an existing directory, so re-assert the mode in
	// case an earlier run or a umask left it readable.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fileProtector{}, fmt.Errorf("secure vault key directory: %w", err)
	}
	return fileProtector{dir: dir}, nil
}

func (p fileProtector) Name() string { return "owner-only key file" }

func (p fileProtector) path(name string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	return filepath.Join(p.dir, name+".key"), nil
}

// Load returns the wrapped key, refusing one whose permissions would let
// another account read it.
func (p fileProtector) Load(name string) (string, error) {
	path, err := p.path(name)
	if err != nil {
		return "", err
	}
	// Lstat, not Stat: a symlink here could redirect the read to a file the
	// user did not intend to treat as key material.
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", vault.ErrKeyMissing
	}
	if err != nil {
		return "", fmt.Errorf("inspect vault key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("vault key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("vault key file %s is group- or world-accessible (%04o); run: chmod 600 %s", path, perm, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read vault key file: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("vault key file %s is empty", path)
	}
	return key, nil
}

// Save writes the wrapped key atomically so an interrupted write cannot leave a
// truncated key that would strand the vault.
func (p fileProtector) Save(name, encodedKey string) error {
	path, err := p.path(name)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(p.dir, ".key-*")
	if err != nil {
		return fmt.Errorf("create temporary vault key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary vault key file: %w", err)
	}
	if _, err := tmp.WriteString(encodedKey); err != nil {
		tmp.Close()
		return fmt.Errorf("write vault key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flush vault key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close vault key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install vault key file: %w", err)
	}
	return nil
}

// noLegacyStore stands in where there is no OS credential manager to migrate
// pre-vault values from. Every Ironrun version that wrote values outside the
// vault required a credential manager, so a vault opened with the file
// protector has no legacy source to read through to.
type noLegacyStore struct{}

func (noLegacyStore) Name() string                    { return "none" }
func (noLegacyStore) Set(_, _, _ string) error        { return ErrUnavailable }
func (noLegacyStore) Get(_, _ string) (string, error) { return "", ErrMissing }
func (noLegacyStore) Delete(_, _ string) error        { return nil }
func (noLegacyStore) DeleteScope(_ string) error      { return nil }
