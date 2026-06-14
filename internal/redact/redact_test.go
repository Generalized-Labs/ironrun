package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

func collect(w *redact.Writer, buf *bytes.Buffer, inputs ...string) string {
	for _, s := range inputs {
		w.Write([]byte(s))
	}
	w.Flush()
	return buf.String()
}

func TestBasicRedaction(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"supersecret"}, 0)
	out := collect(w, &buf, "hello supersecret world")
	if strings.Contains(out, "supersecret") {
		t.Errorf("secret leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("placeholder missing: %q", out)
	}
}

func TestSplitChunkRedaction(t *testing.T) {
	// Secret split across two Write calls.
	var buf bytes.Buffer
	secret := "abc123"
	w := redact.New(&buf, []string{secret}, 0)
	w.Write([]byte("prefix ab"))
	w.Write([]byte("c123 suffix"))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("split-chunk secret leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("placeholder missing after split: %q", out)
	}
}

func TestMultipleSecrets(t *testing.T) {
	var buf bytes.Buffer
	secrets := []string{"password123", "apikey456"}
	w := redact.New(&buf, secrets, 0)
	out := collect(w, &buf, "p=password123 k=apikey456 done")
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("secret %q leaked in: %q", s, out)
		}
	}
}

func TestEmptySecret(t *testing.T) {
	// Empty secret should not cause infinite replacement or panic.
	var buf bytes.Buffer
	w := redact.New(&buf, []string{""}, 0)
	out := collect(w, &buf, "hello world")
	if out != "hello world" {
		t.Errorf("empty secret changed output: %q", out)
	}
}

func TestRepeatedSecret(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"tok"}, 0)
	out := collect(w, &buf, "tok tok tok")
	if strings.Contains(out, "tok") {
		t.Errorf("repeated secret leaked: %q", out)
	}
	count := strings.Count(out, "[REDACTED]")
	if count != 3 {
		t.Errorf("expected 3 replacements, got %d in %q", count, out)
	}
}

func TestMaxOutputBytes(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 10)
	w.Write([]byte("hello world this is a long string"))
	w.Flush()
	out := buf.String()
	if len(out) > 10 {
		t.Errorf("output exceeded max bytes: len=%d %q", len(out), out)
	}
}

func TestNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)
	out := collect(w, &buf, "plain output")
	if out != "plain output" {
		t.Errorf("unexpected modification: %q", out)
	}
}

func TestAddSecretAfterCreation(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)
	w.AddSecret("lateadded")
	out := collect(w, &buf, "value=lateadded here")
	if strings.Contains(out, "lateadded") {
		t.Errorf("late-added secret leaked: %q", out)
	}
}

func TestLongOutput(t *testing.T) {
	// Ensure very long output doesn't hang or OOM.
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"secret"}, 0)
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 100; i++ {
		w.Write([]byte(chunk))
	}
	w.Flush()
	if buf.Len() < 4096*100-10 {
		t.Errorf("too much output lost: got %d bytes", buf.Len())
	}
}

func TestBytesWritten(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)
	w.Write([]byte("hello"))
	w.Flush()
	if w.BytesWritten() != 5 {
		t.Errorf("expected 5 bytes written, got %d", w.BytesWritten())
	}
}
