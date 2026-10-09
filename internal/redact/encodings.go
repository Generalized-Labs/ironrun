package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

// Encodings returns common encodings of secret worth registering for redaction
// in addition to the literal value.
//
// Level 1 (single derivations): base64 (std/raw and url/raw-url) plus its
// cores at the other two byte alignments (see Base64Cores), lower- and
// upper-case hex, percent-encoding as Go, JavaScript and Python escape it in
// both upper- and lower-case %xx form (%2F and %2f must both match), and
// JSON-string escaping (see JSONEscapes).
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
	// Other ecosystems' escapers keep different characters: RFC 3986 /
	// Python quote(safe=''), JS encodeURIComponent, Python quote() (keeps '/').
	for _, safe := range []string{"", "!*'()", "/"} {
		e := percentEncode(secret, safe)
		urlforms = append(urlforms, e, lowerPctEscapes(e))
	}

	candidates := make([]string, 0, 64)
	candidates = append(candidates, b64forms...)
	candidates = append(candidates, Base64Cores(secret)...)
	candidates = append(candidates, hexforms...)
	candidates = append(candidates, urlforms...)
	candidates = append(candidates, JSONEscapes(secret)...)

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

// wrapLines inserts '\n' between every width bytes (openssl/MIME style
// wrapping). No newline follows the last chunk: that newline belongs to the
// surrounding output, and consuming it would join the next line onto the
// placeholder. Inputs shorter than width are returned unchanged.
func wrapLines(s string, width int) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/width)
	for i := 0; i < len(s); i += width {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s[i:min(i+width, len(s))])
	}
	return b.String()
}

// Base64Cores returns, for each byte alignment of secret inside a larger
// base64-encoded message (offset mod 3 = 0, 1, 2), the run of characters
// that depend only on the secret's bytes, in the standard and URL alphabets.
//
// Base64 maps 3-byte groups to 4 characters, so the encoding of a secret that
// follows k bytes of other data (HTTP Basic "user:token", printenv | base64,
// docker "auth") shares no characters with base64(secret) unless k = 0. With
// k leading bytes, the characters whose 6 bits all come from the secret are
// enc(pad_k || s)[ceil(8k/6) : floor(8(k+n)/6)]; the final partial character
// mixes in whatever follows and is dropped.
func Base64Cores(secret string) []string {
	n := len(secret)
	var out []string
	for k := 0; k < 3; k++ {
		padded := append(make([]byte, k), secret...)
		start, end := (8*k+5)/6, 8*(k+n)/6
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			out = append(out, enc.EncodeToString(padded)[start:end])
		}
	}
	return out
}

// JSONEscapes returns secret as it appears inside a JSON string literal when
// that differs from the raw bytes: minimally escaped (", \, control bytes —
// JSON.stringify, Python json.dumps for ASCII) and Go's default HTML-safe form
// (<, >, & as \u003c, \u003e, \u0026).
func JSONEscapes(secret string) []string {
	var out []string
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	if enc.Encode(secret) == nil {
		out = append(out, strings.TrimSuffix(plain.String(), "\n"))
	}
	if b, err := json.Marshal(secret); err == nil {
		out = append(out, string(b))
	}
	for i := range out {
		out[i] = out[i][1 : len(out[i])-1] // drop the quotes
	}
	return out
}

// percentEncode %XX-escapes every byte outside the RFC 3986 unreserved set
// and the extra characters in safe.
func percentEncode(s, safe string) string {
	const hexUp = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~"+safe, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUp[c>>4])
		b.WriteByte(hexUp[c&0xf])
	}
	return b.String()
}
