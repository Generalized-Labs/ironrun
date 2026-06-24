package runner

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// minEncodedVariantLen is the length floor for an ENCODED variant to be
// registered for redaction. Short encodings collide with ordinary output —
// a 4-byte secret hex-encodes to 8 chars (a git short SHA, a CRC), and a tiny
// base64 string appears inside UUIDs and tokens — so redacting them would chew
// up unrelated output while protecting little. We only redact encodings long
// enough to be distinctive.
const minEncodedVariantLen = 8

// minHexSecretLen is the minimum PLAINTEXT length before hex variants are
// registered: an 8-hex-digit string (from a 4-byte secret) is indistinguishable
// from a git short SHA or CRC32, so require >= 8 plaintext bytes (>= 16 hex).
const minHexSecretLen = 8

// SecretVariants returns the literal secret plus the common ENCODINGS an
// approved command might emit it as: base64 (std/url, padded/unpadded), hex
// (lower/upper), and URL escaping (query/path). This catches a command that
// prints, say, a base64-wrapped token, which a literal-only matcher would miss.
//
// To avoid over-redaction, encoded variants must be at least minEncodedVariantLen
// bytes, hex variants require a plaintext of at least minHexSecretLen, and any
// variant equal to the literal (or already seen) is dropped. The literal itself
// is always included — the caller has already applied the literal-length policy.
func SecretVariants(secret string) []string {
	out := []string{secret}
	seen := map[string]bool{secret: true}
	add := func(v string) {
		if v == "" || seen[v] || len(v) < minEncodedVariantLen {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	b := []byte(secret)

	// base64: standard/url alphabets x padded/unpadded.
	add(base64.StdEncoding.EncodeToString(b))
	add(base64.RawStdEncoding.EncodeToString(b))
	add(base64.URLEncoding.EncodeToString(b))
	add(base64.RawURLEncoding.EncodeToString(b))

	// hex (lower + upper) — only for secrets long enough to be distinctive.
	if len(secret) >= minHexSecretLen {
		h := hex.EncodeToString(b)
		add(h)
		add(strings.ToUpper(h))
	}

	// URL escaping (query + path) — only registers when it actually differs.
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))

	return out
}
