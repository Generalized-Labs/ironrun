// Package secrets provides the host-side store used by `ironrun secrets`.
// Plaintext values cross this package boundary only while being injected into
// a child process; they are never serialized into a policy or status response.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/generalized-labs/ironrun/internal/policy"
)

var ErrMissing = errors.New("secret missing")

type Store interface {
	Name() string
	Set(name, value string) error
	Get(name string) (string, error)
	Delete(name string) error
}

// ResolveAliases resolves only aliases explicitly bound to cmd. It deliberately
// returns a generic missing error so callers cannot turn status into disclosure.
func ResolveAliases(f *policy.File, cmd *policy.Command, store Store) (map[string]string, error) {
	out := make(map[string]string, len(cmd.Secrets))
	for _, alias := range cmd.Secrets {
		decl := f.Secrets[alias]
		value, err := store.Get(alias)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMissing, alias)
		}
		out[decl.Env] = value
	}
	return out, nil
}

func Open(policyPath, requested string) (Store, error) {
	if requested == "" || requested == "auto" {
		if runtime.GOOS == "darwin" {
			if _, err := exec.LookPath("security"); err == nil {
				return &keychainStore{service: serviceName(policyPath)}, nil
			}
		}
		return newFileStore(policyPath)
	}
	switch strings.ToLower(requested) {
	case "keychain":
		if runtime.GOOS != "darwin" {
			return nil, fmt.Errorf("keychain storage is currently supported on macOS only")
		}
		return &keychainStore{service: serviceName(policyPath)}, nil
	case "envfile":
		return newFileStore(policyPath)
	default:
		return nil, fmt.Errorf("unknown secret store %q (use auto, keychain, or envfile)", requested)
	}
}

func serviceName(policyPath string) string { return "ironrun/" + hexHash(canonicalPath(policyPath)) }

type keychainStore struct{ service string }

func (k *keychainStore) Name() string { return "macOS Keychain" }
func (k *keychainStore) Set(name, value string) error {
	// Keep the value out of argv/process listings. With -w and no argument,
	// `security` reads the password from stdin.
	cmd := exec.Command("security", "add-generic-password", "-U", "-s", k.service, "-a", name, "-w")
	cmd.Stdin = strings.NewReader(value + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain write failed: %s", safeErr(out))
	}
	return nil
}
func (k *keychainStore) Get(name string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", k.service, "-a", name, "-w").Output()
	if err != nil {
		return "", ErrMissing
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
func (k *keychainStore) Delete(name string) error {
	cmd := exec.Command("security", "delete-generic-password", "-s", k.service, "-a", name)
	if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "could not be found") {
		return fmt.Errorf("keychain delete failed: %s", safeErr(out))
	}
	return nil
}

type fileStore struct {
	dir, keyPath string
	key          []byte
}
type sealedValue struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func newFileStore(policyPath string) (*fileStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".ironrun", "secrets", hexHash(canonicalPath(policyPath)))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create secret store: %w", err)
	}
	keyPath := filepath.Join(dir, ".key")
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		if err = writePrivate(keyPath, key); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("read secret store key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret store key has invalid length")
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return nil, fmt.Errorf("secure secret store key: %w", err)
	}
	return &fileStore{dir: dir, keyPath: keyPath, key: key}, nil
}
func (f *fileStore) Name() string            { return "encrypted local store" }
func (f *fileStore) path(name string) string { return filepath.Join(f.dir, hexHash(name)+".json") }
func (f *fileStore) Set(name, value string) error {
	b, err := aes.NewCipher(f.key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	enc := g.Seal(nil, nonce, []byte(value), []byte(name))
	v := sealedValue{Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(enc)}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writePrivate(f.path(name), data)
}
func (f *fileStore) Get(name string) (string, error) {
	data, err := os.ReadFile(f.path(name))
	if os.IsNotExist(err) {
		return "", ErrMissing
	}
	if err != nil {
		return "", err
	}
	var v sealedValue
	if err := json.Unmarshal(data, &v); err != nil {
		return "", fmt.Errorf("secret store corrupt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(v.Nonce)
	if err != nil {
		return "", ErrMissing
	}
	enc, err := base64.RawStdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		return "", ErrMissing
	}
	b, _ := aes.NewCipher(f.key)
	g, _ := cipher.NewGCM(b)
	plain, err := g.Open(nil, nonce, enc, []byte(name))
	if err != nil {
		return "", ErrMissing
	}
	return string(plain), nil
}
func (f *fileStore) Delete(name string) error {
	err := os.Remove(f.path(name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func writePrivate(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func canonicalPath(path string) string {
	p, err := filepath.Abs(path)
	if err == nil {
		return filepath.Clean(p)
	}
	return path
}
func hexHash(s string) string { sum := sha256.Sum256([]byte(s)); return fmt.Sprintf("%x", sum[:]) }
func safeErr(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		s = s[:240]
	}
	return s
}
