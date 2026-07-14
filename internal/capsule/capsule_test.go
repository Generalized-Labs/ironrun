package capsule

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCapsuleRoundTripTamperExpiryAndBinding(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	m, err := OpenWithKey("project-a", key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	payload := Payload{
		RequestID: "req_123", SessionID: "session-a", Environment: "dev",
		SecretAlias: "openai", SecretKey: "OPENAI_API_KEY", Value: "sk-plaintext-marker",
	}
	sealed, err := m.Seal(payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "ir1.") || strings.Contains(sealed, payload.Value) {
		t.Fatalf("unsafe capsule = %s", sealed)
	}
	got, err := m.Open(sealed)
	if err != nil || got.Value != payload.Value || got.SessionID != payload.SessionID {
		t.Fatalf("opened payload = %#v, %v", got, err)
	}

	tamperedBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		t.Fatal(err)
	}
	tamperedBytes[len(tamperedBytes)/2] ^= 0x01
	tampered := prefix + base64.RawURLEncoding.EncodeToString(tamperedBytes)
	if _, err := m.Open(tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tamper error = %v", err)
	}
	other, _ := OpenWithKey("project-b", key)
	if _, err := other.Open(sealed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-project error = %v", err)
	}
	m.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := m.Open(sealed); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error = %v", err)
	}
}
