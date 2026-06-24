package redact

import (
	"math"
	"regexp"
)

// EntropyHit describes a high-entropy, secret-shaped token that survived
// redaction (i.e. it did not match any registered secret value). It is a
// best-effort warning signal only — ironrun never alters output based on it,
// and the token is reported so callers can warn without echoing it elsewhere.
type EntropyHit struct {
	Token   string
	Entropy float64 // Shannon entropy, bits per character
	Offset  int     // byte offset of the token within the scanned string
}

const (
	entropyMinTokenLen = 20
	entropyThreshold   = 3.5 // bits per character
)

// entropyTokenRe matches plausible credential tokens. Path/word separators like
// '/', '.', ':' are intentionally excluded so file paths and dotted identifiers
// split into short pieces rather than registering as one long token.
var entropyTokenRe = regexp.MustCompile(`[A-Za-z0-9_-]{20,}`)

// benignShapes are tokens that look high-entropy but are commonly benign; they
// would otherwise be noisy false positives.
var benignShapes = []*regexp.Regexp{
	regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`), // UUID
	regexp.MustCompile(`^[0-9a-fA-F]{40}$`), // git SHA-1
	regexp.MustCompile(`^[0-9a-fA-F]{64}$`), // SHA-256 hex digest
	regexp.MustCompile(`^[0-9]+$`),          // pure numeric (ids, epoch timestamps)
}

// ScanHighEntropy returns secret-shaped, high-entropy tokens in s. A hit means
// "this looks like it might be an unredacted secret", not a confirmed leak —
// it is used as a warn-only backstop to the literal redactor.
func ScanHighEntropy(s string) []EntropyHit {
	var hits []EntropyHit
	for _, loc := range entropyTokenRe.FindAllStringIndex(s, -1) {
		tok := s[loc[0]:loc[1]]
		if isBenignShape(tok) || !looksTokenish(tok) {
			continue
		}
		if e := shannonEntropy(tok); e >= entropyThreshold {
			hits = append(hits, EntropyHit{Token: tok, Entropy: e, Offset: loc[0]})
		}
	}
	return hits
}

func isBenignShape(tok string) bool {
	for _, re := range benignShapes {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}

// looksTokenish filters out plain prose: a real credential almost always mixes
// character classes (contains a digit, or both letter cases), whereas a single
// long word is one case with no digits.
func looksTokenish(tok string) bool {
	var hasDigit, hasUpper, hasLower bool
	for _, r := range tok {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		}
	}
	return hasDigit || (hasUpper && hasLower)
}

// shannonEntropy returns the Shannon entropy of s in bits per byte.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
