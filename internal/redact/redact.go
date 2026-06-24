// Package redact provides streaming secret redaction for subprocess output.
//
// The core primitive is a Writer that wraps an underlying io.Writer and
// replaces any occurrence of registered secret values with "[REDACTED]".
//
// Secrets may be split across Write calls (e.g. a secret like "abc123"
// split as "ab" then "c123"). The scanner approach handles this by processing
// the buffer byte-by-byte: a byte is only emitted once we've confirmed that no
// registered secret starts there (or the secret has been fully matched and
// replaced). We always hold back (maxLen-1) bytes so a secret spanning two
// Write calls is still detected.
package redact

import (
	"io"
	"sort"
	"sync"
)

const placeholder = "[REDACTED]"

// Writer is a streaming redacting writer. It is safe for concurrent use.
type Writer struct {
	mu      sync.Mutex
	out     io.Writer
	secrets [][]byte // sorted longest-first so we greedily match the longest secret
	buf     []byte   // rolling buffer — holds unprocessed bytes
	maxLen  int      // max length of any secret
	written int64    // total bytes written to out
	maxOut  int64    // 0 = unlimited

	redactions int64 // count of secret occurrences replaced with the placeholder
}

// New creates a Writer that redacts all values in secrets before writing to out.
// maxOutputBytes caps total output (0 = unlimited).
func New(out io.Writer, secrets []string, maxOutputBytes int64) *Writer {
	w := &Writer{out: out, maxOut: maxOutputBytes}
	for _, s := range secrets {
		if s == "" {
			continue // ignore empty secrets — they'd match everything
		}
		b := []byte(s)
		w.secrets = append(w.secrets, b)
		if len(b) > w.maxLen {
			w.maxLen = len(b)
		}
	}
	// Sort longest-first for greedy matching.
	sort.Slice(w.secrets, func(i, j int) bool {
		return len(w.secrets[i]) > len(w.secrets[j])
	})
	return w
}

// Write implements io.Writer. It appends data to the rolling buffer,
// then advances the scanner: each byte is emitted only once we know it
// cannot be part of an unprocessed secret.
func (w *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf = append(w.buf, p...)
	if err := w.scan(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush forces all buffered bytes to be scanned, redacted, and written.
// Must be called after the subprocess exits.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.scan(true)
}

// scan advances the scanner through w.buf.
// If final is true, all remaining bytes are emitted.
// If final is false, we hold back (maxLen-1) bytes at the tail so that a
// secret spanning the current/next Write boundary is still detected.
func (w *Writer) scan(final bool) error {
	for {
		// How many bytes must we keep in the buffer before emitting?
		// If not final: keep (maxLen-1) bytes so a secret can't be missed.
		// If final: process everything.
		hold := 0
		if !final && w.maxLen > 1 {
			hold = w.maxLen - 1
		}

		if len(w.buf) <= hold {
			break // not enough data to safely process anything
		}

		// Try to match a secret at position 0.
		matched := false
		for _, secret := range w.secrets {
			if len(secret) > len(w.buf) {
				// Secret longer than buffer — might still match once more data arrives.
				// Skip for now; will be caught later (or on Flush).
				continue
			}
			if hasPrefix(w.buf, secret) {
				// Full match — emit placeholder, advance past the secret.
				if err := w.emit([]byte(placeholder)); err != nil {
					return err
				}
				w.redactions++
				w.buf = w.buf[len(secret):]
				matched = true
				break
			}
		}

		if !matched {
			// No secret starts here. Emit one byte.
			if err := w.emit(w.buf[:1]); err != nil {
				return err
			}
			w.buf = w.buf[1:]
		}
	}
	return nil
}

// emit writes data to the underlying writer, respecting the maxOut cap.
func (w *Writer) emit(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if w.maxOut > 0 {
		remaining := w.maxOut - w.written
		if remaining <= 0 {
			return nil
		}
		if int64(len(data)) > remaining {
			data = data[:remaining]
		}
	}
	n, err := w.out.Write(data)
	w.written += int64(n)
	return err
}

// BytesWritten returns the number of bytes written to the underlying writer.
func (w *Writer) BytesWritten() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

// RedactionCount returns the number of secret occurrences replaced so far.
func (w *Writer) RedactionCount() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.redactions
}

// AddSecret registers an additional secret value for redaction.
// Thread-safe; can be called after the writer is in use.
func (w *Writer) AddSecret(s string) {
	if s == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	b := []byte(s)
	w.secrets = append(w.secrets, b)
	if len(b) > w.maxLen {
		w.maxLen = len(b)
	}
	// Re-sort longest-first.
	sort.Slice(w.secrets, func(i, j int) bool {
		return len(w.secrets[i]) > len(w.secrets[j])
	})
}

// hasPrefix reports whether b starts with prefix.
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i, c := range prefix {
		if b[i] != c {
			return false
		}
	}
	return true
}
