package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

func collectV2(w *redact.Writer, buf *bytes.Buffer, inputs ...string) string {
	for _, s := range inputs {
		if _, err := w.Write([]byte(s)); err != nil {
			panic(err)
		}
	}
	if err := w.Flush(); err != nil {
		panic(err)
	}
	return buf.String()
}

// interleave inserts gap bytes between every character of s.
func interleave(s string, gap byte) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		if i > 0 {
			b.WriteByte(gap)
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// =====================================================
// Tier 2: whitespace/control-char tolerant matching
// =====================================================

func TestFlex_ControlCharSmuggling(t *testing.T) {
	// The "sk-abc\x1bdef" class: ESC interleaved between every secret char.
	secret := "sk-abcdef1234567890ABCDEF" // 24 chars
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "leak:"+interleave(secret, 0x1b)+":end")
	if strings.Contains(out, "sk-") {
		t.Errorf("control-char-smuggled secret leaked: %q", out)
	}
	if out != "leak:[REDACTED]:end" {
		t.Errorf("expected %q, got %q", "leak:[REDACTED]:end", out)
	}
}

func TestFlex_WhitespaceSplit(t *testing.T) {
	// Secret split by spaces, tabs and newlines.
	secret := "whitespace-split-secret-12345678"
	split := strings.Join([]string{"whit", "esp", "ace-", "spli", "t-se", "cret", "-123", "4567", "8"}, "\n")
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "v="+split+" end")
	if strings.Contains(out, "whit") || strings.Contains(out, "4567") {
		t.Errorf("whitespace-split secret leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("placeholder missing: %q", out)
	}
}

func TestFlex_SplitAcrossWriteBoundary(t *testing.T) {
	// Interstitial whitespace straddles two Write calls.
	secret := "boundary-flex-secret-abcdef123456"
	half := len(secret) / 2
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf,
		"a "+interleave(secret[:half], ' '),
		"\n"+interleave(secret[half:], '\t')+" z",
	)
	if strings.Contains(out, secret[:12]) {
		t.Errorf("cross-chunk flex secret leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("placeholder missing: %q", out)
	}
}

func TestFlex_PartialPrefixNotConsumed(t *testing.T) {
	// A failed flex match must not consume or alter output.
	secret := "ABCDEF"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "ABC XYZ")
	if out != "ABC XYZ" {
		t.Errorf("partial prefix altered: %q", out)
	}
}

func TestFlex_TrailingGapPreserved(t *testing.T) {
	// Whitespace AFTER the matched secret is legitimate output, not smuggling.
	secret := "abcdef"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "x a\tb\nc d\te\nf y")
	if out != "x [REDACTED] y" {
		t.Errorf("expected %q, got %q", "x [REDACTED] y", out)
	}
}

func TestFlex_NullBytesIgnored(t *testing.T) {
	// NUL bytes interleaved in a printed secret.
	secret := "null-sandwich-secret-1234567890"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "v="+interleave(secret, 0x00)+"!")
	if strings.Contains(out, "null-sandwich") {
		t.Errorf("NUL-smuggled secret leaked: %q", out)
	}
}

func TestFlex_SecretWithOwnWhitespace(t *testing.T) {
	// A secret that itself contains whitespace matches its compacted form.
	secret := "multi word secret value 123456"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	compact := strings.ReplaceAll(secret, " ", "")
	out := collectV2(w, &buf, "v="+compact+" end")
	if strings.Contains(out, compact) {
		t.Errorf("compacted secret leaked: %q", out)
	}
}

// =====================================================
// Tier 3: fragment matching (12+ char substrings of long secrets)
// =====================================================

func TestFragment_TruncatedSecret(t *testing.T) {
	// A pasted 20-char fragment of a 40-char secret is redacted.
	secret := "fragment-secret-abcdefghijklmnopqrstuvwxyz12"
	frag := secret[5:25]
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "pasted "+frag+" here")
	if strings.Contains(out, frag) {
		t.Errorf("secret fragment leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("placeholder missing: %q", out)
	}
}

func TestFragment_ExactlyTwelveChars(t *testing.T) {
	// The minimum 12-char fragment still triggers redaction.
	secret := strings.Repeat("Ab3", 20) // 60 chars
	frag := secret[10:22]
	if len(frag) != 12 {
		t.Fatalf("test setup: frag len %d", len(frag))
	}
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, ">"+frag+"<")
	if strings.Contains(out, frag) {
		t.Errorf("12-char fragment leaked: %q", out)
	}
	if out != ">[REDACTED]<" {
		t.Errorf("expected %q, got %q", ">[REDACTED]<", out)
	}
}

func TestFragment_ExtendsToFullRun(t *testing.T) {
	// The whole contiguous run is redacted, not just the first 12 bytes.
	secret := "extend-run-secret-0123456789ABCDEFGHIJ"
	frag := secret[4:24] // 20 chars
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, ">"+frag+"<")
	if out != ">[REDACTED]<" {
		t.Errorf("expected %q, got %q", ">[REDACTED]<", out)
	}
	if w.RedactionCount() != 1 {
		t.Errorf("expected 1 redaction, got %d", w.RedactionCount())
	}
}

func TestFragment_SplitAcrossWrites(t *testing.T) {
	// A fragment straddling a Write boundary is still caught.
	secret := "cross-chunk-fragment-secret-xyz1234567890"
	frag := secret[8:28]
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "aa "+frag[:10], frag[10:]+" bb")
	if strings.Contains(out, frag) {
		t.Errorf("cross-chunk fragment leaked: %q", out)
	}
}

func TestFragment_ShortSecretThreshold(t *testing.T) {
	// Fragment matching only applies to long secrets (>= 24 chars):
	// a 12-char fragment of a 16-char secret is NOT redacted, but the full
	// value still is. This pins the documented threshold.
	secret := "sixteen-char-123" // 16 chars
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectV2(w, &buf, "xx "+secret[:12]+" yy")
	if !strings.Contains(out, secret[:12]) {
		t.Errorf("short-secret fragment unexpectedly redacted: %q", out)
	}

	var buf2 bytes.Buffer
	w2 := redact.New(&buf2, []string{secret}, 0)
	out2 := collectV2(w2, &buf2, "xx "+secret+" yy")
	if strings.Contains(out2, secret) {
		t.Errorf("full short secret leaked: %q", out2)
	}
}

func TestFragment_EncodedVariantFragment(t *testing.T) {
	// Fragments of registered encoded variants are caught too: a truncated
	// base64 form still redacts.
	secret := "variant-fragment-secret-value-1234567890"
	variants := redact.Encodings(secret, 8)
	var buf bytes.Buffer
	w := redact.New(&buf, append([]string{secret}, variants...), 0)
	// Take a 20-char slice of the std-base64 variant.
	b64 := variants[0]
	frag := b64[5:25]
	out := collectV2(w, &buf, "b64frag="+frag+" end")
	if strings.Contains(out, frag) {
		t.Errorf("encoded-variant fragment leaked: %q", out)
	}
}
