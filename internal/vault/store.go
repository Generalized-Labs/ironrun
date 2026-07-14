// Package vault implements Ironrun's encrypted, project-scoped environment
// store. Secret names and values are encrypted at rest; only project identity,
// environment scope names, format metadata, and ciphertext are visible.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	formatVersion = 1
	cipherName    = "AES-256-GCM+wrapped-scope-keys"
	rootKeySize   = 32
)

var (
	ErrMissing    = errors.New("vault value missing")
	ErrKeyMissing = errors.New("vault root key missing")
	ErrIntegrity  = errors.New("vault integrity check failed")
)

// Protector persists the project root key in a platform credential manager.
// Implementations must return ErrKeyMissing only when the named key is absent.
type Protector interface {
	Load(name string) (string, error)
	Save(name, encodedKey string) error
}

// Store is a small encrypted document optimized for developer environment
// sets. Rewriting a scope rotates that scope's data-encryption key.
type Store struct {
	path      string
	projectID string
	rootKey   []byte
	now       func() time.Time
}

type document struct {
	Version   int                    `json:"version"`
	Cipher    string                 `json:"cipher"`
	ProjectID string                 `json:"project_id"`
	Revision  uint64                 `json:"revision"`
	UpdatedAt time.Time              `json:"updated_at"`
	Scopes    map[string]sealedScope `json:"scopes"`
	MAC       string                 `json:"mac"`
}

type sealedScope struct {
	KeyNonce   string `json:"key_nonce"`
	WrappedKey string `json:"wrapped_key"`
	DataNonce  string `json:"data_nonce"`
	Ciphertext string `json:"ciphertext"`
}

type scopePayload struct {
	Values map[string]string `json:"values"`
}

// DefaultDir returns the per-user location for encrypted vault documents.
// It is intentionally outside project repositories.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ironrun", "vaults"), nil
}

// Open loads or initializes a project vault. If a vault document already
// exists but its protected root key is missing, Open fails closed rather than
// silently creating a replacement key that could never decrypt the document.
func Open(dir, projectID string, protector Protector) (*Store, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, errors.New("vault project id cannot be empty")
	}
	if protector == nil {
		return nil, errors.New("vault key protector is required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure vault directory: %w", err)
	}

	path := filepath.Join(dir, projectFilename(projectID))
	keyName := "project-" + shortHash(projectID)
	encoded, err := protector.Load(keyName)
	if err != nil {
		if !errors.Is(err, ErrKeyMissing) {
			return nil, fmt.Errorf("load protected vault key: %w", err)
		}
		if _, statErr := os.Stat(path); statErr == nil {
			return nil, fmt.Errorf("%w: encrypted vault exists at %s", ErrKeyMissing, path)
		} else if !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("inspect vault: %w", statErr)
		}
		key := make([]byte, rootKeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generate vault key: %w", err)
		}
		encoded = base64.RawStdEncoding.EncodeToString(key)
		if err := protector.Save(keyName, encoded); err != nil {
			zero(key)
			return nil, fmt.Errorf("protect vault key: %w", err)
		}
		zero(key)
	}

	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != rootKeySize {
		return nil, errors.New("protected vault key has invalid encoding or length")
	}
	s := &Store{path: path, projectID: projectID, rootKey: key, now: time.Now}
	if _, err := s.load(); err != nil {
		zero(key)
		return nil, err
	}
	return s, nil
}

// OpenWithKey is intended for tests and recovery tooling that already owns key
// acquisition. Production callers should use Open with an OS-backed Protector.
func OpenWithKey(path, projectID string, key []byte) (*Store, error) {
	if len(key) != rootKeySize {
		return nil, errors.New("vault root key must be 32 bytes")
	}
	if strings.TrimSpace(projectID) == "" {
		return nil, errors.New("vault project id cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	s := &Store{path: path, projectID: projectID, rootKey: append([]byte(nil), key...), now: time.Now}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Path() string { return s.path }

// Set atomically replaces one value and rotates the scope data key.
func (s *Store) Set(scope, key, value string) error {
	if err := validate(scope, "scope"); err != nil {
		return err
	}
	if err := validate(key, "key"); err != nil {
		return err
	}
	return s.withLock(func() error {
		doc, err := s.load()
		if err != nil {
			return err
		}
		payload := scopePayload{Values: map[string]string{}}
		if sealed, ok := doc.Scopes[scope]; ok {
			payload, err = s.openScope(scope, sealed)
			if err != nil {
				return err
			}
		}
		payload.Values[key] = value
		sealed, err := s.sealScope(scope, payload)
		if err != nil {
			return err
		}
		doc.Scopes[scope] = sealed
		doc.Revision++
		doc.UpdatedAt = s.now().UTC()
		return s.save(doc)
	})
}

func (s *Store) Get(scope, key string) (string, error) {
	if err := validate(scope, "scope"); err != nil {
		return "", err
	}
	if err := validate(key, "key"); err != nil {
		return "", err
	}
	doc, err := s.load()
	if err != nil {
		return "", err
	}
	sealed, ok := doc.Scopes[scope]
	if !ok {
		return "", ErrMissing
	}
	payload, err := s.openScope(scope, sealed)
	if err != nil {
		return "", err
	}
	value, ok := payload.Values[key]
	if !ok {
		return "", ErrMissing
	}
	return value, nil
}

func (s *Store) Delete(scope, key string) error {
	if err := validate(scope, "scope"); err != nil {
		return err
	}
	if err := validate(key, "key"); err != nil {
		return err
	}
	return s.withLock(func() error {
		doc, err := s.load()
		if err != nil {
			return err
		}
		sealed, ok := doc.Scopes[scope]
		if !ok {
			return nil
		}
		payload, err := s.openScope(scope, sealed)
		if err != nil {
			return err
		}
		if _, ok := payload.Values[key]; !ok {
			return nil
		}
		delete(payload.Values, key)
		if len(payload.Values) == 0 {
			delete(doc.Scopes, scope)
		} else {
			doc.Scopes[scope], err = s.sealScope(scope, payload)
			if err != nil {
				return err
			}
		}
		doc.Revision++
		doc.UpdatedAt = s.now().UTC()
		return s.save(doc)
	})
}

// DeleteScope cryptographically erases an environment by removing its wrapped
// data key and ciphertext from the next committed vault revision.
func (s *Store) DeleteScope(scope string) error {
	if err := validate(scope, "scope"); err != nil {
		return err
	}
	return s.withLock(func() error {
		doc, err := s.load()
		if err != nil {
			return err
		}
		if _, ok := doc.Scopes[scope]; !ok {
			return nil
		}
		delete(doc.Scopes, scope)
		doc.Revision++
		doc.UpdatedAt = s.now().UTC()
		return s.save(doc)
	})
}

func (s *Store) load() (document, error) {
	doc := document{
		Version:   formatVersion,
		Cipher:    cipherName,
		ProjectID: s.projectID,
		Scopes:    map[string]sealedScope{},
	}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return doc, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("read vault: %w", err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return document{}, fmt.Errorf("parse vault: %w", ErrIntegrity)
	}
	if doc.Version != formatVersion || doc.Cipher != cipherName || doc.ProjectID != s.projectID {
		return document{}, fmt.Errorf("%w: unexpected format or project identity", ErrIntegrity)
	}
	if doc.Scopes == nil {
		doc.Scopes = map[string]sealedScope{}
	}
	if err := s.verifyMAC(doc); err != nil {
		return document{}, err
	}
	return doc, nil
}

func (s *Store) save(doc document) error {
	doc.MAC = ""
	mac, err := s.computeMAC(doc)
	if err != nil {
		return err
	}
	doc.MAC = base64.RawStdEncoding.EncodeToString(mac)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create vault transaction: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write vault transaction: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync vault transaction: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("commit vault transaction: %w", err)
	}
	committed = true
	if err := os.Chmod(s.path, 0600); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (s *Store) sealScope(scope string, payload scopePayload) (sealedScope, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return sealedScope{}, err
	}
	dataKey := make([]byte, rootKeySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return sealedScope{}, err
	}
	defer zero(dataKey)

	dataAEAD, err := newAEAD(dataKey)
	if err != nil {
		return sealedScope{}, err
	}
	dataNonce := make([]byte, dataAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return sealedScope{}, err
	}
	ciphertext := dataAEAD.Seal(nil, dataNonce, plain, s.scopeAAD("data", scope))

	rootAEAD, err := newAEAD(s.rootKey)
	if err != nil {
		return sealedScope{}, err
	}
	keyNonce := make([]byte, rootAEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, keyNonce); err != nil {
		return sealedScope{}, err
	}
	wrapped := rootAEAD.Seal(nil, keyNonce, dataKey, s.scopeAAD("key", scope))
	return sealedScope{
		KeyNonce:   encode(keyNonce),
		WrappedKey: encode(wrapped),
		DataNonce:  encode(dataNonce),
		Ciphertext: encode(ciphertext),
	}, nil
}

func (s *Store) openScope(scope string, sealed sealedScope) (scopePayload, error) {
	keyNonce, err := decode(sealed.KeyNonce)
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	wrapped, err := decode(sealed.WrappedKey)
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	rootAEAD, err := newAEAD(s.rootKey)
	if err != nil {
		return scopePayload{}, err
	}
	dataKey, err := rootAEAD.Open(nil, keyNonce, wrapped, s.scopeAAD("key", scope))
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	defer zero(dataKey)
	dataNonce, err := decode(sealed.DataNonce)
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	ciphertext, err := decode(sealed.Ciphertext)
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	dataAEAD, err := newAEAD(dataKey)
	if err != nil {
		return scopePayload{}, err
	}
	plain, err := dataAEAD.Open(nil, dataNonce, ciphertext, s.scopeAAD("data", scope))
	if err != nil {
		return scopePayload{}, ErrIntegrity
	}
	var payload scopePayload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Values == nil {
		return scopePayload{}, ErrIntegrity
	}
	return payload, nil
}

func (s *Store) verifyMAC(doc document) error {
	provided, err := decode(doc.MAC)
	if err != nil || len(provided) == 0 {
		return ErrIntegrity
	}
	doc.MAC = ""
	expected, err := s.computeMAC(doc)
	if err != nil {
		return err
	}
	if !hmac.Equal(provided, expected) {
		return ErrIntegrity
	}
	return nil
}

func (s *Store) computeMAC(doc document) ([]byte, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, s.rootKey)
	_, _ = mac.Write([]byte("ironrun-vault-manifest-v1\x00"))
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}

func (s *Store) scopeAAD(kind, scope string) []byte {
	return []byte(fmt.Sprintf("ironrun-vault-v%d\x00%s\x00%s\x00%s", formatVersion, kind, s.projectID, scope))
}

func (s *Store) withLock(fn func() error) error {
	lockPath := s.path + ".lock"
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Mkdir(lockPath, 0700)
		if err == nil {
			defer os.Remove(lockPath) //nolint:errcheck
			return fn()
		}
		if !os.IsExist(err) {
			return fmt.Errorf("acquire vault lock: %w", err)
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for vault lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validate(value, label string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("vault %s cannot be empty", label)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("vault %s contains a NUL byte", label)
	}
	return nil
}

func encode(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }
func decode(value string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(value)
}
func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}
func projectFilename(projectID string) string { return shortHash(projectID) + ".irvault" }
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
