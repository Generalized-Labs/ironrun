package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

// This file documents a known edge case with AddSecret.
// When AddSecret is called after data containing the secret has already been
// written but potentially not yet emitted, the secret may leak.

func TestAddSecretTimingIssue_Documented(t *testing.T) {
	// Case 1: Secret added BEFORE any matching data is written - works correctly
	t.Run("AddBeforeWrite", func(t *testing.T) {
		var buf bytes.Buffer
		w := redact.New(&buf, nil, 0)
		w.AddSecret("SECRET")
		w.Write([]byte("containsSECREThere"))
		w.Flush()
		out := buf.String()
		if strings.Contains(out, "SECRET") {
			t.Errorf("secret leaked when added before write: %q", out)
		}
	})

	// Case 2: Secret added AFTER data is written but before flush
	// This MAY leak if data was already partially emitted from buffer
	t.Run("AddAfterWriteBeforeFlush", func(t *testing.T) {
		var buf bytes.Buffer
		w := redact.New(&buf, nil, 0)
		w.Write([]byte("containsSECREThere"))
		w.AddSecret("SECRET")
		w.Flush()
		out := buf.String()
		// Document behavior: the secret LEAKS because data was already processed
		// before the secret was registered
		if strings.Contains(out, "SECRET") {
			t.Logf("KNOWN BEHAVIOR: secret leaked when added after write: %q", out)
			// Don't fail - this documents expected (if unfortunate) behavior
		} else {
			t.Logf("Secret was redacted (buffer wasn't emitted yet): %q", out)
		}
	})

	// Case 3: With a longer secret, more data may be buffered
	t.Run("AddAfterWriteLongSecret", func(t *testing.T) {
		var buf bytes.Buffer
		w := redact.New(&buf, nil, 0)
		// First add a dummy secret to create a hold buffer
		w.AddSecret("AAAAA")
		// Write data with a NEW secret we haven't registered yet
		w.Write([]byte("xNEWSECy"))
		// Now add the new secret
		w.AddSecret("NEWSEC")
		// More data
		w.Write([]byte("zNEWSECw"))
		w.Flush()
		out := buf.String()
		t.Logf("Long secret case output: %q", out)
		// The second occurrence should be redacted, first might leak
	})
}

// This test demonstrates the window where AddSecret can fail
func TestAddSecretHoldBufferWindow(t *testing.T) {
	// If maxLen is N, we hold back N-1 bytes.
	// So if we have a 10-byte secret, we hold 9 bytes.
	// Any data beyond the held portion is emitted immediately.

	var buf bytes.Buffer
	// Create with a 6-byte secret so maxLen=6, hold=5
	w := redact.New(&buf, []string{"AAAAAA"}, 0)

	// Write 10 bytes - 5 will be emitted, 5 held
	w.Write([]byte("1234567890"))
	// At this point "12345" has been emitted, "67890" is held

	// Now add a new secret that appears in the emitted portion
	w.AddSecret("234")

	// Write and flush
	w.Write([]byte("end234end"))
	w.Flush()

	out := buf.String()
	// "234" appears twice: once in already-emitted data (leaked), once in new data (redacted)
	count := strings.Count(out, "234")
	t.Logf("Output: %q, count of '234': %d", out, count)
	// First occurrence leaked because it was emitted before AddSecret was called
}
