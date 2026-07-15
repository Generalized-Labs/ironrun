// Package capsule creates short-lived, project- and session-bound ciphertext
// that may be pasted through a chat transcript without exposing its plaintext.
package capsule

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
)

const (
	prefix     = "ir1."
	keySize    = 32
	DefaultTTL = 5 * time.Minute
	MaxTTL     = 10 * time.Minute
)

var (
	ErrInvalid = errors.New("invalid encrypted capsule")
	ErrExpired = errors.New("encrypted capsule expired")
)

type Payload struct {
	Version     int       `json:"version"`
	RequestID   string    `json:"request_id"`
	SessionID   string    `json:"session_id"`
	Environment string    `json:"environment"`
	SecretAlias string    `json:"secret_alias"`
	SecretKey   string    `json:"secret_key"`
	Value       string    `json:"value"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Manager struct {
	projectID string
	key       []byte
	now       func() time.Time
}

// Open acquires a project capsule key from the native credential manager.
func Open(root string) (*Manager, error) {
	identity, err := envset.DiscoverIdentity(root)
	if err != nil {
		return nil, err
	}
	projectID := identityID(identity)
	store, err := envset.OpenNative()
	if err != nil {
		return nil, err
	}
	name := "project-" + projectID[:32]
	encoded, err := store.Get("capsule-keys", name)
	if err != nil {
		if !errors.Is(err, envset.ErrMissing) {
			return nil, fmt.Errorf("load capsule key: %w", err)
		}
		key := make([]byte, keySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		encoded = base64.RawStdEncoding.EncodeToString(key)
		if err := store.Set("capsule-keys", name, encoded); err != nil {
			zero(key)
			return nil, fmt.Errorf("protect capsule key: %w", err)
		}
		zero(key)
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != keySize {
		return nil, errors.New("protected capsule key has invalid encoding or length")
	}
	return &Manager{projectID: projectID, key: key, now: time.Now}, nil
}

func OpenWithKey(projectID string, key []byte) (*Manager, error) {
	if strings.TrimSpace(projectID) == "" || len(key) != keySize {
		return nil, errors.New("capsule project id and 32-byte key are required")
	}
	return &Manager{projectID: projectID, key: append([]byte(nil), key...), now: time.Now}, nil
}

func (m *Manager) Seal(payload Payload, ttl time.Duration) (string, error) {
	if err := validate(payload); err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return "", fmt.Errorf("capsule ttl exceeds maximum %s", MaxTTL)
	}
	payload.Version = 1
	payload.ExpiresAt = m.now().UTC().Add(ttl)
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(m.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, plain, m.aad())
	data := append(nonce, sealed...)
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func (m *Manager) Open(capsule string) (Payload, error) {
	if !strings.HasPrefix(capsule, prefix) {
		return Payload{}, ErrInvalid
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(capsule, prefix))
	if err != nil {
		return Payload{}, ErrInvalid
	}
	aead, err := newAEAD(m.key)
	if err != nil {
		return Payload{}, err
	}
	if len(data) <= aead.NonceSize() {
		return Payload{}, ErrInvalid
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], m.aad())
	if err != nil {
		return Payload{}, ErrInvalid
	}
	var payload Payload
	if err := json.Unmarshal(plain, &payload); err != nil || payload.Version != 1 {
		return Payload{}, ErrInvalid
	}
	if err := validate(payload); err != nil {
		return Payload{}, ErrInvalid
	}
	if !m.now().UTC().Before(payload.ExpiresAt) {
		return Payload{}, ErrExpired
	}
	return payload, nil
}

func validate(p Payload) error {
	if strings.TrimSpace(p.RequestID) == "" || strings.TrimSpace(p.SessionID) == "" ||
		strings.TrimSpace(p.Environment) == "" || strings.TrimSpace(p.SecretAlias) == "" ||
		strings.TrimSpace(p.SecretKey) == "" || p.Value == "" {
		return errors.New("capsule payload is incomplete")
	}
	return nil
}

func (m *Manager) aad() []byte { return []byte("ironrun-chat-capsule-v1\x00" + m.projectID) }
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func identityID(identity envset.Identity) string {
	sum := sha256.Sum256([]byte(identity.RemoteURL + "\x00" + identity.CanonicalPath))
	return hex.EncodeToString(sum[:])
}
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
