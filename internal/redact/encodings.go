package redact

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

// Encodings returns common encodings of secret worth registering for redaction
// in addition to the literal value: base64 (std/raw and url/raw-url), lower- and
// upper-case hex, and URL query/path escaping.
//
// A process that base64- or hex-encodes a secret before printing it defeats
// literal matching (the stdout analog of "network exfil by an approved binary").
// Registering these forms closes the accidental-encoded-leak gap.
//
// Derivations shorter than minLen, equal to the original, or duplicates are
// dropped: a short or identical encoding would over-redact ordinary output while
// protecting nothing new.
func Encodings(secret string, minLen int) []string {
	if secret == "" {
		return nil
	}
	raw := []byte(secret)
	candidates := []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
		hex.EncodeToString(raw),
		strings.ToUpper(hex.EncodeToString(raw)),
		url.QueryEscape(secret),
		url.PathEscape(secret),
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
