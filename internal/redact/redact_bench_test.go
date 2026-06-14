package redact_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/redact"
)

func BenchmarkNoSecrets(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, nil, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkOneSecret(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	secrets := []string{"secret123456"}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkTenSecrets(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	secrets := make([]string, 10)
	for i := 0; i < 10; i++ {
		secrets[i] = strings.Repeat(string(rune('A'+i)), 20)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkHundredSecrets(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	secrets := make([]string, 100)
	for i := 0; i < 100; i++ {
		secrets[i] = strings.Repeat(string(rune('A'+i%26)), 20)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkWithMatches(b *testing.B) {
	// Data containing secrets that need to be replaced
	secrets := []string{"SECRET"}
	data := []byte(strings.Repeat("xSECRETy", 512)) // 4KB with many matches
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkLargeOutput(b *testing.B) {
	// 1MB output
	data := []byte(strings.Repeat("x", 1024*1024))
	secrets := []string{"findme", "another", "secret123"}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

func BenchmarkSmallWrites(b *testing.B) {
	// Many small writes
	secrets := []string{"secret"}
	data := []byte("x")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		for j := 0; j < 1000; j++ {
			w.Write(data)
		}
		w.Flush()
	}
}

func BenchmarkLongSecret(b *testing.B) {
	// Secret that's 1KB long
	secrets := []string{strings.Repeat("S", 1024)}
	data := []byte(strings.Repeat("x", 4096))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets, 0)
		w.Write(data)
		w.Flush()
	}
}

// Baseline comparison - direct write without redaction
func BenchmarkDirectWrite(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		buf.Write(data)
	}
}

// Compare with io.Discard to measure pure overhead
func BenchmarkDiscardNoSecrets(b *testing.B) {
	data := []byte(strings.Repeat("x", 4096))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := redact.New(io.Discard, nil, 0)
		w.Write(data)
		w.Flush()
	}
}
