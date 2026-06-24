package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncodings_RedactsBase64AndHex(t *testing.T) {
	secret := "sk_live_super_secret_value_1234"
	variants := Encodings(secret, 8)

	// The base64 and hex forms must be among the derived variants.
	wantB64 := base64.StdEncoding.EncodeToString([]byte(secret))
	wantHex := hex.EncodeToString([]byte(secret))
	if !contains(variants, wantB64) {
		t.Errorf("std base64 form not derived: %q not in %v", wantB64, variants)
	}
	if !contains(variants, wantHex) {
		t.Errorf("hex form not derived: %q not in %v", wantHex, variants)
	}

	// A writer registered with the variants must redact the encoded forms.
	var buf bytes.Buffer
	w := New(&buf, append([]string{secret}, variants...), 0)
	line := "leaked b64=" + wantB64 + " hex=" + wantHex + " end"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	got := buf.String()
	if strings.Contains(got, wantB64) {
		t.Errorf("base64 form leaked through redactor: %q", got)
	}
	if strings.Contains(got, wantHex) {
		t.Errorf("hex form leaked through redactor: %q", got)
	}
}

func TestEncodings_DropsShortAndIdentical(t *testing.T) {
	// QueryEscape of a plain alphanumeric value equals the value, so it must be
	// dropped (== original); and nothing shorter than minLen survives.
	secret := "abcdefghij" // 10 alphanumerics, url-escape == itself
	variants := Encodings(secret, 8)
	for _, v := range variants {
		if v == secret {
			t.Errorf("derivation equal to original was not dropped: %q", v)
		}
		if len(v) < 8 {
			t.Errorf("derivation shorter than minLen=8 was not dropped: %q", v)
		}
	}
}

func TestEncodings_EmptySecret(t *testing.T) {
	if got := Encodings("", 8); got != nil {
		t.Errorf("expected nil for empty secret, got %v", got)
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
