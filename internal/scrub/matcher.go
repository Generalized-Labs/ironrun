// Package scrub implements exact-value secret matching and redaction.
//
// Unlike regex/entropy scanners, ironrun knows the exact secret values it
// manages, so matching is exact: the literal value plus the encoded variants
// tools routinely persist (base64, base64-url, percent-encoding). This keeps
// false positives near zero: a match is only reported when bytes ironrun
// itself issued appear in the scanned text.
//
// The variant set reuses internal/redact's base64 alignment cores and JSON
// escapes, so transcripts (which store tool output JSON-escaped) and CI masks
// cover the same shapes the streaming redactor does.
package scrub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/generalized-labs/ironrun/internal/redact"
)

// MinSecretLen is the minimum byte length of a value eligible for matching.
// Shorter values are skipped: a 3-byte token matches everywhere and would
// drown real findings in false positives.
const MinSecretLen = 8

// Secret is one managed value to match, identified by its vault alias.
type Secret struct {
	Alias string
	Value string
}

// Sha8 returns the first 8 hex chars of sha256(value). It lets the user
// correlate a redaction marker back to the alias without revealing the value.
func Sha8(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:8]
}

// Placeholder is the replacement text for a matched value.
func Placeholder(alias, value string) string {
	return "[REDACTED:" + alias + ":" + Sha8(value) + "]"
}

// Variants returns the exact value plus the encoded spellings tools persist:
// base64 (padded + raw), base64-url (padded + raw), base64 at the other two
// byte alignments, percent-encoding (uppercase and lowercase hex), and
// JSON-string escaping. Duplicates, no-op and too-short encodings are dropped.
func Variants(value string) []string {
	out := []string{value}
	seen := map[string]bool{value: true}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	b := []byte(value)
	add(base64.StdEncoding.EncodeToString(b))
	add(base64.RawStdEncoding.EncodeToString(b))
	add(base64.URLEncoding.EncodeToString(b))
	add(base64.RawURLEncoding.EncodeToString(b))
	add(percentEncode(b, true))
	add(percentEncode(b, false))
	for _, v := range append(redact.Base64Cores(value), redact.JSONEscapes(value)...) {
		if len(v) >= MinSecretLen {
			add(v)
		}
	}
	return out
}

// percentEncode percent-encodes every byte outside the RFC 3986 unreserved
// set. upper selects %2F vs %2f hex case; both occur in the wild.
func percentEncode(b []byte, upper bool) string {
	const digitsUp = "0123456789ABCDEF"
	const digitsLo = "0123456789abcdef"
	digits := digitsUp
	if !upper {
		digits = digitsLo
	}
	var sb strings.Builder
	changed := false
	for _, c := range b {
		if c == '-' || c == '_' || c == '.' || c == '~' ||
			(c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') {
			sb.WriteByte(c)
			continue
		}
		changed = true
		sb.WriteByte('%')
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0xf])
	}
	if !changed {
		return string(b) // identical to the input; caller dedupes
	}
	return sb.String()
}

type trieNode struct {
	next map[byte]*trieNode
	repl string // non-empty at terminal nodes: replacement text
}

// Matcher redacts every known value (and its encoded variants) from text in
// a single left-to-right pass, longest match winning at each position.
type Matcher struct {
	root    *trieNode
	secrets []Secret // secrets that contributed at least one needle
	needles int
	skipped int // aliases skipped (empty / too short)
}

// NewMatcher builds a matcher from managed secrets. Values shorter than
// MinSecretLen are skipped. Duplicate values keep the first alias.
func NewMatcher(secrets []Secret) *Matcher {
	m := &Matcher{root: &trieNode{}}
	seenValue := map[string]bool{}
	for _, s := range secrets {
		if len(s.Value) < MinSecretLen {
			m.skipped++
			continue
		}
		if seenValue[s.Value] {
			continue
		}
		seenValue[s.Value] = true
		repl := Placeholder(s.Alias, s.Value)
		for _, v := range Variants(s.Value) {
			m.insert(v, repl)
			m.needles++
		}
		m.secrets = append(m.secrets, s)
	}
	return m
}

func (m *Matcher) insert(needle, repl string) {
	n := m.root
	for i := 0; i < len(needle); i++ {
		c := needle[i]
		if n.next == nil {
			n.next = map[byte]*trieNode{}
		}
		child, ok := n.next[c]
		if !ok {
			child = &trieNode{}
			n.next[c] = child
		}
		n = child
	}
	// First alias wins on exact needle collisions across secrets.
	if n.repl == "" {
		n.repl = repl
	}
}

// Secrets returns the secrets that contributed needles to the matcher.
func (m *Matcher) Secrets() []Secret { return m.secrets }

// Needles returns the number of distinct match strings indexed.
func (m *Matcher) Needles() int { return m.needles }

// Skipped returns the number of aliases skipped (empty or too-short values).
func (m *Matcher) Skipped() int { return m.skipped }

// Redact replaces every known value/variant in s with its placeholder.
// It returns the redacted text and the number of replacements made.
// Redact is idempotent: redacting already-redacted text changes nothing.
func (m *Matcher) Redact(s string) (string, int) {
	if m.needles == 0 || len(s) == 0 {
		return s, 0
	}
	var sb strings.Builder
	sb.Grow(len(s))
	count := 0
	i := 0
	for i < len(s) {
		n := m.root
		longest := -1
		longestRepl := ""
		for j := i; j < len(s); j++ {
			child := n.next[s[j]]
			if child == nil {
				break
			}
			n = child
			if n.repl != "" {
				longest = j + 1
				longestRepl = n.repl
			}
		}
		if longest == -1 {
			sb.WriteByte(s[i])
			i++
			continue
		}
		sb.WriteString(longestRepl)
		count++
		i = longest
	}
	return sb.String(), count
}

// Contains reports whether s holds any known value or variant.
func (m *Matcher) Contains(s string) bool {
	_, n := m.Redact(s)
	return n > 0
}
