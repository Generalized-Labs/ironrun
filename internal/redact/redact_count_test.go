package redact_test

import (
	"bytes"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

// The Redactions() count is the per-run trust signal ("N secret values redacted").

func TestRedactions_Count(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"PWD"}, 0)
	collect(w, &buf, "xPWDyPWDz") // two occurrences
	if got := w.Redactions(); got != 2 {
		t.Errorf("Redactions() = %d, want 2", got)
	}
}

func TestRedactions_Zero(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"secretvalue"}, 0)
	collect(w, &buf, "nothing to see here")
	if got := w.Redactions(); got != 0 {
		t.Errorf("Redactions() = %d, want 0", got)
	}
}

func TestRedactions_SplitCountsOnce(t *testing.T) {
	// A secret split across two Write calls is one logical redaction.
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"abc123"}, 0)
	w.Write([]byte("ab"))
	w.Write([]byte("c123"))
	w.Flush()
	if got := w.Redactions(); got != 1 {
		t.Errorf("Redactions() across split = %d, want 1", got)
	}
}
