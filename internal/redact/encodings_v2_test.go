package redact

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// TestEncodings_WrappedBase64: openssl-style (64-col) and MIME-style (76-col)
// wrapped base64 forms are registered as variants and redacted end-to-end.
func TestEncodings_WrappedBase64(t *testing.T) {
	// Long enough that std base64 exceeds 64 chars and actually wraps.
	secret := strings.Repeat("s3cr3t-value-", 10) // 130 chars
	variants := Encodings(secret, 8)

	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	w64, w76 := wrapLines(b64, 64), wrapLines(b64, 76)
	if w64 == b64 || w76 == b64 {
		t.Fatalf("test setup: base64 %d chars did not wrap", len(b64))
	}
	if !contains(variants, w64) {
		t.Errorf("64-col wrapped base64 not derived")
	}
	if !contains(variants, w76) {
		t.Errorf("76-col wrapped base64 not derived")
	}

	var buf bytes.Buffer
	w := New(&buf, append([]string{secret}, variants...), 0)
	if _, err := w.Write([]byte("key:\n" + w64 + "end")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), b64[:32]) {
		t.Errorf("wrapped base64 leaked: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "[REDACTED]") {
		t.Errorf("placeholder missing: %q", buf.String())
	}
}

// TestEncodings_LowercasePctEscapes: %2f must match as well as %2F.
func TestEncodings_LowercasePctEscapes(t *testing.T) {
	secret := "p@ss/w:rd+value1234"
	variants := Encodings(secret, 8)

	upper := url.QueryEscape(secret)
	lower := lowerPctEscapes(upper)
	if upper == lower {
		t.Fatalf("test setup: no %%XX escapes in %q", upper)
	}
	if !strings.Contains(upper, "%2F") {
		t.Fatalf("test setup: expected uppercase escapes in %q", upper)
	}
	if !contains(variants, upper) {
		t.Errorf("uppercase QueryEscape not derived: %q", upper)
	}
	if !contains(variants, lower) {
		t.Errorf("lowercase QueryEscape not derived: %q", lower)
	}

	var buf bytes.Buffer
	w := New(&buf, append([]string{secret}, variants...), 0)
	if _, err := w.Write([]byte("q=" + lower + " end")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), lower) {
		t.Errorf("lowercase percent-encoding leaked: %q", buf.String())
	}
}

// TestEncodings_Recursive: base64(base64(v)), urlencode(base64(v)) and
// hex(base64(v)) are derived; depth 1 excludes them.
func TestEncodings_Recursive(t *testing.T) {
	secret := "sk_live_abcdefghij1234567890"
	variants := Encodings(secret, 8)

	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	nested := map[string]string{
		"b64(b64)": base64.StdEncoding.EncodeToString([]byte(b64)),
		"url(b64)": url.QueryEscape(b64),
		"hex(b64)": hexEncode(b64),
	}
	for name, want := range nested {
		if !contains(variants, want) {
			t.Errorf("%s not derived: %q", name, want)
		}
	}

	shallow := EncodingsWithDepth(secret, 8, 1)
	for name, want := range nested {
		if contains(shallow, want) {
			t.Errorf("depth=1 should not derive %s", name)
		}
	}

	// End-to-end: nested encoding through the writer is redacted.
	var buf bytes.Buffer
	w := New(&buf, append([]string{secret}, variants...), 0)
	line := "nested=" + nested["b64(b64)"] + " url=" + nested["url(b64)"] + " end"
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	for name, want := range nested {
		if strings.Contains(buf.String(), want) {
			t.Errorf("%s leaked: %q", name, buf.String())
		}
	}
}

// TestEncodings_EmbeddedContexts: base64 values wrapped in quotes, JSON
// string context, or affixed with prefixes/suffixes are caught because
// matching is substring-based.
func TestEncodings_EmbeddedContexts(t *testing.T) {
	secret := "tok_embedded_secret_value_99"
	variants := Encodings(secret, 8)
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))

	var buf bytes.Buffer
	w := New(&buf, append([]string{secret}, variants...), 0)
	inputs := []string{
		`{"api_key": "` + b64 + `"}`,
		`token='` + b64 + `' done`,
		`prefix:` + b64 + `:suffix`,
		"  \t" + b64 + "\n",
	}
	for _, in := range inputs {
		if _, err := w.Write([]byte(in)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), b64) {
		t.Errorf("embedded base64 leaked: %q", buf.String())
	}
	if got := strings.Count(buf.String(), "[REDACTED]"); got != len(inputs) {
		t.Errorf("expected %d redactions, got %d in %q", len(inputs), got, buf.String())
	}
}

// TestEncodings_DepthZeroBehavesLikeOne: degenerate depth values don't panic
// and behave like depth 1.
func TestEncodings_DepthZeroBehavesLikeOne(t *testing.T) {
	secret := "depth_check_secret_12345678"
	d0 := EncodingsWithDepth(secret, 8, 0)
	d1 := EncodingsWithDepth(secret, 8, 1)
	if len(d0) != len(d1) {
		t.Errorf("depth 0 (%d variants) != depth 1 (%d variants)", len(d0), len(d1))
	}
}

func hexEncode(s string) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		b.WriteByte(digits[s[i]>>4])
		b.WriteByte(digits[s[i]&0x0f])
	}
	return b.String()
}
