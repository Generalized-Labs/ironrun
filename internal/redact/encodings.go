package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// Encodings returns common encodings of secret worth registering for redaction
// in addition to the literal value.
//
// Level 1 (single derivations): base64 (std/raw and url/raw-url), lower- and
// upper-case hex, and URL query/path escaping in both upper- and lower-case
// %xx hex form (%2F and %2f must both match — some encoders emit lowercase).
//
// Level 2 (nested derivations): the level-1 transforms applied again to each
// level-1 base64/hex derivation, catching base64(base64(v)),
// urlencode(base64(v)), hex(base64(v)) and similar nestings.
//
// Wrapped variants: base64 forms re-wrapped with newlines at 64 columns
// (openssl default) and 76 columns (MIME), so wrapped output is caught by
// exact match in addition to the whitespace-tolerant matcher.
//
// A process that encodes a secret before printing it defeats literal matching
// (the stdout analog of "network exfil by an approved binary"). Registering
// these forms closes the accidental-encoded-leak gap.
//
// Derivations shorter than minLen, equal to the original, or duplicates are
// dropped: a short or identical encoding would over-redact ordinary output
// while protecting nothing new.
func Encodings(secret string, minLen int) []string {
	return EncodingsWithDepth(secret, minLen, 2)
}

// EncodingsWithDepth is Encodings with an explicit nesting depth: depth 1
// returns single derivations only, depth 2 (the default via Encodings) adds
// the nested level-2 derivations. Depth < 1 behaves like depth 1.
func EncodingsWithDepth(secret string, minLen, depth int) []string {
	if secret == "" {
		return nil
	}
	raw := []byte(secret)

	b64forms := []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	}
	hexforms := []string{
		hex.EncodeToString(raw),
		strings.ToUpper(hex.EncodeToString(raw)),
	}
	qesc := url.QueryEscape(secret)
	pesc := url.PathEscape(secret)
	urlforms := []string{qesc, lowerPctEscapes(qesc), pesc, lowerPctEscapes(pesc)}

	candidates := make([]string, 0, 64)
	candidates = append(candidates, b64forms...)
	candidates = append(candidates, hexforms...)
	candidates = append(candidates, urlforms...)

	if depth >= 2 {
		// Nested encodings: apply the second-level transforms to each
		// level-1 base64/hex derivation. URL-escaped forms are deliberately
		// excluded as inputs here — urlencode(urlencode(x)) style nesting is
		// rare in practice and the cartesian product is the main cost driver.
		for _, l1 := range append(append([]string{}, b64forms...), hexforms...) {
			candidates = append(candidates, deriveNested(l1)...)
		}
	}

	// Wrapped base64: openssl-style (64 cols) and MIME-style (76 cols)
	// line wrapping. Short forms wrap to themselves and dedupe out.
	for _, b64 := range b64forms {
		candidates = append(candidates, wrapLines(b64, 64), wrapLines(b64, 76))
	}

	seen := map[string]bool{secret: true}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if len(c) < minLen || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// deriveNested returns second-level encodings of an already-encoded secret
// form: base64-of-base64, urlencode-of-base64, hex-of-base64, etc.
func deriveNested(encoded string) []string {
	b := []byte(encoded)
	q := url.QueryEscape(encoded)
	return []string{
		base64.StdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		q,
		lowerPctEscapes(q),
	}
}

// lowerPctEscapes lowercases the hex digits of %XX escapes: %2F -> %2f.
// Non-escape '%' sequences are left untouched.
func lowerPctEscapes(s string) string {
	out := []byte(s)
	for i := 0; i+2 < len(out); i++ {
		if out[i] == '%' {
			out[i+1] = lowerHexDigit(out[i+1])
			out[i+2] = lowerHexDigit(out[i+2])
			i += 2
		}
	}
	return string(out)
}

func lowerHexDigit(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
}

// wrapLines inserts '\n' every width bytes (openssl/MIME style wrapping).
// Inputs shorter than width are returned unchanged.
func wrapLines(s string, width int) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/width + 1)
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}
