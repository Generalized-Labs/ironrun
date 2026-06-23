package redact

import "testing"

func TestScanHighEntropy_FlagsRandomToken(t *testing.T) {
	// A 32-char mixed-case+digit token — the shape of a real API key.
	s := "output: aZ3kP9wQ1xR7mB2nF5tL8vC4yH6jD0sG end"
	hits := ScanHighEntropy(s)
	if len(hits) == 0 {
		t.Fatalf("expected a high-entropy hit, got none")
	}
}

func TestScanHighEntropy_NoFalsePositives(t *testing.T) {
	benign := []struct {
		name string
		s    string
	}{
		{"uuid", "id=550e8400-e29b-41d4-a716-446655440000 done"},
		{"git_sha1", "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"},
		{"sha256_hex", "sum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"prose", "the quick brown fox jumps over the lazy sleeping dog today"},
		{"path", "writing to /home/user/.local/state/ironrun/audit.log now"},
		{"semver", "ironrun version 1.2.3 built today"},
		{"timestamp", "ts 2026-06-23T12:34:56.789Z recorded"},
		{"numeric_id", "run id 1234567890123456 finished"},
	}
	for _, b := range benign {
		if hits := ScanHighEntropy(b.s); len(hits) != 0 {
			t.Errorf("%s: expected no hits, got %d: %+v", b.name, len(hits), hits)
		}
	}
}

func TestScanHighEntropy_DoesNotMutate(t *testing.T) {
	// Sanity: the scanner is read-only (warn-first posture); it returns hits but
	// the caller's string is untouched (strings are immutable in Go, but assert
	// the offset/token reporting is consistent).
	s := "tok aZ3kP9wQ1xR7mB2nF5tL8vC4yH6jD0sG end"
	hits := ScanHighEntropy(s)
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 hit, got %d", len(hits))
	}
	h := hits[0]
	if s[h.Offset:h.Offset+len(h.Token)] != h.Token {
		t.Errorf("reported offset %d does not point at token %q", h.Offset, h.Token)
	}
}
