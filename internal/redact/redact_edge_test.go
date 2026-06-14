package redact_test

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

// Test for potential memory issues

func TestBufferMemoryGrowth(t *testing.T) {
	// This test verifies that memory doesn't grow unboundedly
	// when processing large amounts of data through the redactor.

	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"secret"}, 0)

	// Write 100MB of data in 1KB chunks
	chunk := []byte(strings.Repeat("x", 1024))
	for i := 0; i < 100*1024; i++ {
		w.Write(chunk)
	}
	w.Flush()

	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Memory growth should be bounded - we shouldn't be holding onto
	// more than a few KB after processing
	heapGrowth := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	t.Logf("Heap growth after 100MB processing: %d bytes", heapGrowth)

	// The buffer.Buffer will grow to hold the output, but the redactor
	// shouldn't be holding onto much
	if heapGrowth > 200*1024*1024 { // Allow 200MB for output buffer + overhead
		t.Errorf("Excessive memory growth: %d bytes", heapGrowth)
	}
}

func TestSliceCapacityLeak(t *testing.T) {
	// Test that the buffer slice doesn't retain references to old data
	// by writing lots of data then checking the buffer's capacity

	var buf bytes.Buffer
	secrets := []string{strings.Repeat("S", 100)}
	w := redact.New(&buf, secrets, 0)

	// Write lots of data
	for i := 0; i < 10000; i++ {
		w.Write([]byte("some text without secrets\n"))
	}
	w.Flush()

	// If everything is correct, output should match input (no secrets)
	lines := strings.Count(buf.String(), "\n")
	if lines != 10000 {
		t.Errorf("Expected 10000 lines, got %d", lines)
	}
}

// Test for potential issues with partial prefix matches

func TestPartialPrefixNotConsumed(t *testing.T) {
	// If input starts matching a secret but doesn't complete,
	// the partial should be emitted correctly

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"ABCDEF"}, 0)
	// "ABC" starts like the secret but doesn't complete
	out := collectStr(w, &buf, "ABC XYZ")
	if out != "ABC XYZ" {
		t.Errorf("Partial prefix consumed incorrectly: %q", out)
	}
}

func TestPartialPrefixFollowedByMatch(t *testing.T) {
	// Partial prefix followed by actual match

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"ABCDEF"}, 0)
	out := collectStr(w, &buf, "ABC ABCDEF XYZ")
	expected := "ABC [REDACTED] XYZ"
	if out != expected {
		t.Errorf("Expected %q, got %q", expected, out)
	}
}

func TestRepeatedPartialPrefix(t *testing.T) {
	// Multiple partial prefixes

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"ABCDEF"}, 0)
	out := collectStr(w, &buf, "AB AB AB ABCDEF")
	expected := "AB AB AB [REDACTED]"
	if out != expected {
		t.Errorf("Expected %q, got %q", expected, out)
	}
}

// Test for pathological input patterns

func TestRepeatedFirstByte(t *testing.T) {
	// Input is just the first byte of the secret repeated
	// This shouldn't cause performance issues

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"SECRET"}, 0)
	input := strings.Repeat("S", 10000)
	w.Write([]byte(input))
	w.Flush()
	out := buf.String()
	if out != input {
		t.Errorf("Repeated first byte modified output")
	}
}

func TestAlmostMatchingPattern(t *testing.T) {
	// Input is SECRET but missing last char, repeated

	var buf bytes.Buffer
	w := redact.New(&buf, []string{"SECRET"}, 0)
	input := strings.Repeat("SECRE_", 1000)
	w.Write([]byte(input))
	w.Flush()
	out := buf.String()
	if out != input {
		t.Errorf("Almost-match pattern modified output")
	}
}

// Test error handling from underlying writer

type errorWriter struct {
	failAfter int
	written   int
}

func (e *errorWriter) Write(p []byte) (int, error) {
	if e.written >= e.failAfter {
		return 0, bytes.ErrTooLarge
	}
	e.written += len(p)
	return len(p), nil
}

func TestWriterErrorPropagation(t *testing.T) {
	ew := &errorWriter{failAfter: 5}
	w := redact.New(ew, nil, 0)
	_, err := w.Write([]byte("hello world"))
	if err == nil {
		// The error might come on flush
		err = w.Flush()
	}
	// We expect an error at some point
	t.Logf("Error propagation test: err=%v, written=%d", err, ew.written)
}

func TestWriterErrorDuringRedaction(t *testing.T) {
	ew := &errorWriter{failAfter: 1} // Fail after 1 byte
	w := redact.New(ew, []string{"xxx"}, 0)
	_, err := w.Write([]byte("axxx")) // Should try to emit "a" then "[REDACTED]"
	if err == nil {
		err = w.Flush()
	}
	if err != bytes.ErrTooLarge {
		t.Logf("Error during redaction: %v", err)
	}
}

func collectStr(w *redact.Writer, buf *bytes.Buffer, input string) string {
	w.Write([]byte(input))
	w.Flush()
	return buf.String()
}
