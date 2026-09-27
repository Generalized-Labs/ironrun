package redact

import "testing"

// TestScanHighEntropy_SymbolAlphabet: tokens using the full symbol alphabet
// (+, /, =, ~!#$%&) are now tokenized and flagged.
func TestScanHighEntropy_SymbolAlphabet(t *testing.T) {
	cases := []struct {
		name string
		s    string
	}{
		{"base64_symbols", "leak aB3+xY9/qW2=zR5+tU8/vX1yZ end"},
		{"base64_padding", "tok dGhpcyBpcyBhIHRlc3Qgc2VjcmV0ISE= end"},
		{"symbol_mix", "key ~!#aB3$%&xY9*@?qW2zR5tU8v end"},
	}
	for _, c := range cases {
		hits := ScanHighEntropy(c.s)
		if len(hits) == 0 {
			t.Errorf("%s: expected a hit for symbol-alphabet token in %q", c.name, c.s)
		}
	}
}

// TestScanHighEntropy_AssignmentPrefix: a "key=" prefix glued onto a token by
// the '=' alphabet char must not defeat the benign-shape filter, and a random
// value behind "key=" must still warn (reporting the value part).
func TestScanHighEntropy_AssignmentPrefix(t *testing.T) {
	if hits := ScanHighEntropy("id=550e8400-e29b-41d4-a716-446655440000 done"); len(hits) != 0 {
		t.Errorf("uuid behind assignment prefix: expected no hits, got %+v", hits)
	}

	hits := ScanHighEntropy("api_key=aZ3kP9wQ1xR7mB2nF5tL8vC4yH6jD0sG end")
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for key=value token, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Token != "aZ3kP9wQ1xR7mB2nF5tL8vC4yH6jD0sG" {
		t.Errorf("expected value part reported, got %q", h.Token)
	}
}

// TestScanHighEntropy_PathSeparatorsExcluded: '.', ':' and friends still split
// tokens so paths and timestamps don't warn.
func TestScanHighEntropy_PathSeparatorsExcluded(t *testing.T) {
	benign := []string{
		"open /etc/ironrun/config.yaml for reading",
		"at 2026-09-27T12:00:00.000Z the job ran",
		"version 10.20.30 released",
	}
	for _, s := range benign {
		if hits := ScanHighEntropy(s); len(hits) != 0 {
			t.Errorf("expected no hits for %q, got %+v", s, hits)
		}
	}
}
