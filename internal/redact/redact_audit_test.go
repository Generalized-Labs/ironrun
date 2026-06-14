package redact_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/generalized-labs/ironrun/internal/redact"
)

// =====================================================
// CROSS-CHUNK SECRET SPLITTING TESTS
// =====================================================

func TestSplitAtEveryBoundary(t *testing.T) {
	// Split secret at every possible boundary
	secret := "SECRET123"
	for i := 1; i < len(secret); i++ {
		var buf bytes.Buffer
		w := redact.New(&buf, []string{secret}, 0)
		w.Write([]byte("prefix " + secret[:i]))
		w.Write([]byte(secret[i:] + " suffix"))
		w.Flush()
		out := buf.String()
		if strings.Contains(out, secret) {
			t.Errorf("split at %d: secret leaked: %q", i, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("split at %d: placeholder missing: %q", i, out)
		}
		expected := "prefix [REDACTED] suffix"
		if out != expected {
			t.Errorf("split at %d: expected %q, got %q", i, expected, out)
		}
	}
}

func TestSplitAcrossThreeChunks(t *testing.T) {
	// Secret split across THREE write calls
	secret := "ABCDEF"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	w.Write([]byte("AB"))
	w.Write([]byte("CD"))
	w.Write([]byte("EF"))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("three-chunk split secret leaked: %q", out)
	}
}

func TestSecretAtExactChunkBoundary(t *testing.T) {
	// Secret starts exactly at the hold boundary
	secret := "SECRET"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	// Write enough data that the secret begins exactly at the held-back portion
	w.Write([]byte("x"))
	w.Write([]byte("SECRET"))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("secret at boundary leaked: %q", out)
	}
}

// =====================================================
// OVERLAPPING SECRETS TESTS
// =====================================================

func TestOverlappingSecrets(t *testing.T) {
	// Secrets that overlap: "abc" and "abcd"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"abc", "abcd"}, 0)
	out := collectString(w, &buf, "xabcdy")
	// Should match longest first (abcd)
	if strings.Contains(out, "abc") {
		t.Errorf("overlapping secrets leaked: %q", out)
	}
	if strings.Count(out, "[REDACTED]") != 1 {
		t.Errorf("expected 1 redaction, got: %q", out)
	}
}

func TestPrefixSecrets(t *testing.T) {
	// "abc" is prefix of "abcdef"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"abc", "abcdef"}, 0)
	out := collectString(w, &buf, "xabcdefyabcz")
	// "abcdef" should be matched first, then "abc"
	expected := "x[REDACTED]y[REDACTED]z"
	if out != expected {
		t.Errorf("prefix secrets: expected %q, got %q", expected, out)
	}
}

func TestSecretContainsAnotherSecret(t *testing.T) {
	// Secret "XSECRETY" contains "SECRET"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"XSECRETY", "SECRET"}, 0)
	// Input contains the longer secret - should redact just once
	out := collectString(w, &buf, "aXSECRETYb")
	if strings.Contains(out, "SECRET") {
		t.Errorf("secret leaked in nested case: %q", out)
	}
	if strings.Count(out, "[REDACTED]") != 1 {
		t.Errorf("expected 1 redaction, got: %q", out)
	}
}

func TestAdjacentSecrets(t *testing.T) {
	// Two secrets back-to-back
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"AAA", "BBB"}, 0)
	out := collectString(w, &buf, "AAABBB")
	expected := "[REDACTED][REDACTED]"
	if out != expected {
		t.Errorf("adjacent secrets: expected %q, got %q", expected, out)
	}
}

// =====================================================
// UNICODE HANDLING TESTS
// =====================================================

func TestUnicodeSecret(t *testing.T) {
	// Secret contains unicode
	secret := "密码钥匙"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "前缀"+secret+"后缀")
	if strings.Contains(out, secret) {
		t.Errorf("unicode secret leaked: %q", out)
	}
}

func TestUnicodeSplitAtCharBoundary(t *testing.T) {
	// Split unicode secret at a valid character boundary
	secret := "密码"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	// Each Chinese char is 3 bytes in UTF-8
	secretBytes := []byte(secret)
	w.Write(secretBytes[:3]) // First char
	w.Write(secretBytes[3:]) // Second char
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("unicode split secret leaked: %q", out)
	}
}

func TestUnicodeSplitMidCharacter(t *testing.T) {
	// Split in the middle of a UTF-8 sequence
	// This is tricky because the redactor works at byte level
	secret := "密码"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	secretBytes := []byte(secret)
	// Split in the middle of first character (at byte 2 of a 3-byte char)
	w.Write(secretBytes[:2])
	w.Write(secretBytes[2:])
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("unicode mid-char split secret leaked: %q", out)
	}
	// Verify output is still valid UTF-8
	if !utf8.ValidString(out) {
		t.Errorf("output is invalid UTF-8: %q", out)
	}
}

func TestMixedASCIIUnicode(t *testing.T) {
	// Secret with mixed ASCII and unicode
	secret := "pass密码123"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "data:"+secret+":end")
	if strings.Contains(out, secret) {
		t.Errorf("mixed secret leaked: %q", out)
	}
}

func TestEmoji(t *testing.T) {
	// Emoji are 4 bytes in UTF-8
	secret := "🔑key🔐"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "token="+secret+"!")
	if strings.Contains(out, secret) {
		t.Errorf("emoji secret leaked: %q", out)
	}
}

// =====================================================
// EMPTY AND EDGE CASE TESTS
// =====================================================

func TestEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"secret"}, 0)
	w.Write([]byte{})
	w.Flush()
	if buf.Len() != 0 {
		t.Errorf("empty input produced output: %q", buf.String())
	}
}

func TestOnlyEmptySecrets(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"", "", ""}, 0)
	out := collectString(w, &buf, "hello")
	if out != "hello" {
		t.Errorf("empty secrets changed output: %q", out)
	}
}

func TestSingleByteSecret(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"x"}, 0)
	out := collectString(w, &buf, "axbxcx")
	if strings.Contains(out, "x") {
		t.Errorf("single-byte secret leaked: %q", out)
	}
	expected := "a[REDACTED]b[REDACTED]c[REDACTED]"
	if out != expected {
		t.Errorf("expected %q, got %q", expected, out)
	}
}

func TestSingleByteSplit(t *testing.T) {
	// Single byte secrets - no cross-chunk issue possible
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"x"}, 0)
	w.Write([]byte("ax"))
	w.Write([]byte("bx"))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, "x") {
		t.Errorf("single-byte split secret leaked: %q", out)
	}
}

func TestSecretEqualsInput(t *testing.T) {
	// Input is exactly the secret
	secret := "EXACTLY"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, secret)
	if out != "[REDACTED]" {
		t.Errorf("exact match: expected [REDACTED], got %q", out)
	}
}

func TestDuplicateSecrets(t *testing.T) {
	// Same secret registered twice
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"dup", "dup"}, 0)
	out := collectString(w, &buf, "xdupy")
	if strings.Contains(out, "dup") {
		t.Errorf("duplicate secret leaked: %q", out)
	}
	if strings.Count(out, "[REDACTED]") != 1 {
		t.Errorf("expected 1 redaction for duplicate, got: %q", out)
	}
}

func TestVeryLongSecret(t *testing.T) {
	// Secret longer than typical buffer sizes
	secret := strings.Repeat("S", 8192)
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "prefix"+secret+"suffix")
	if strings.Contains(out, secret) {
		t.Errorf("long secret leaked")
	}
	expected := "prefix[REDACTED]suffix"
	if out != expected {
		t.Errorf("long secret: expected %q, got %q", expected, out)
	}
}

func TestVeryLongSecretSplitChunk(t *testing.T) {
	// Long secret split across chunks
	secret := strings.Repeat("X", 1000)
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	// Split at position 500
	w.Write([]byte(secret[:500]))
	w.Write([]byte(secret[500:]))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("long split secret leaked")
	}
}

// =====================================================
// PERFORMANCE / STRESS TESTS
// =====================================================

func TestManySecrets(t *testing.T) {
	// Test with many secrets
	secrets := make([]string, 100)
	for i := 0; i < 100; i++ {
		secrets[i] = strings.Repeat(string(rune('a'+i%26)), 10)
	}
	var buf bytes.Buffer
	w := redact.New(&buf, secrets, 0)
	// Write input containing some of the secrets
	input := "prefix " + secrets[0] + " middle " + secrets[50] + " end"
	out := collectString(w, &buf, input)
	if strings.Contains(out, secrets[0]) || strings.Contains(out, secrets[50]) {
		t.Errorf("secret leaked with many secrets: %q", out)
	}
}

func TestRapidSmallWrites(t *testing.T) {
	// Many tiny writes
	secret := "FINDME"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	input := "beforeFINDMEafter"
	for _, c := range input {
		w.Write([]byte(string(c)))
	}
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("rapid small writes leaked: %q", out)
	}
}

func TestByteByByteWrite(t *testing.T) {
	// Write byte-by-byte
	secret := "TOKEN"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	input := []byte("xTOKENy")
	for _, b := range input {
		w.Write([]byte{b})
	}
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("byte-by-byte leaked: %q", out)
	}
}

func TestLargeInputWithManyMatches(t *testing.T) {
	// Large input with many secret occurrences
	secret := "PWD"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	// 10000 occurrences
	input := strings.Repeat("xPWDy", 10000)
	w.Write([]byte(input))
	w.Flush()
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("large input with matches leaked")
	}
	count := strings.Count(out, "[REDACTED]")
	if count != 10000 {
		t.Errorf("expected 10000 redactions, got %d", count)
	}
}

// =====================================================
// CONCURRENCY TESTS
// =====================================================

func TestConcurrentWrites(t *testing.T) {
	secret := "CONCURRENT_SECRET"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)

	var wg sync.WaitGroup
	// 10 goroutines writing concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				w.Write([]byte("data"))
			}
		}(i)
	}
	wg.Wait()
	w.Flush()
	// Just verify no panic/race - output order is non-deterministic
}

func TestConcurrentAddSecret(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)

	var wg sync.WaitGroup
	// Add secrets and write concurrently
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			w.AddSecret(strings.Repeat(string(rune('A'+n)), 5))
		}(i)
		go func() {
			defer wg.Done()
			w.Write([]byte("test"))
		}()
	}
	wg.Wait()
	w.Flush()
	// Just verify no panic/race
}

// =====================================================
// MAX OUTPUT BYTES TESTS
// =====================================================

func TestMaxOutputCutsRedaction(t *testing.T) {
	// Max output that cuts in middle of [REDACTED]
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"secret"}, 5)
	w.Write([]byte("secret"))
	w.Flush()
	out := buf.String()
	if len(out) > 5 {
		t.Errorf("exceeded max bytes: %d > 5: %q", len(out), out)
	}
	// Should be "[REDA" (first 5 chars of [REDACTED])
	if out != "[REDA" {
		t.Errorf("expected '[REDA', got %q", out)
	}
}

func TestMaxOutputExactBoundary(t *testing.T) {
	// Max output exactly at redaction boundary
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"x"}, 10) // [REDACTED] is 10 chars
	w.Write([]byte("x"))
	w.Flush()
	out := buf.String()
	if out != "[REDACTED]" {
		t.Errorf("expected exact [REDACTED], got %q", out)
	}
}

func TestMaxOutputZeroAfterFirst(t *testing.T) {
	// Max output reached, subsequent writes ignored
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 5)
	w.Write([]byte("hello"))
	w.Write([]byte("world"))
	w.Flush()
	out := buf.String()
	if out != "hello" {
		t.Errorf("expected 'hello', got %q", out)
	}
}

// =====================================================
// ADD SECRET AFTER CREATION TESTS
// =====================================================

func TestAddSecretMidStream(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)
	w.Write([]byte("before"))
	w.AddSecret("NEWSECRET")
	w.Write([]byte("NEWSECRET"))
	w.Flush()
	out := buf.String()
	// The "before" part should pass through, but NEWSECRET should be redacted
	if !strings.HasPrefix(out, "before") {
		t.Errorf("prefix lost: %q", out)
	}
	if strings.Contains(out, "NEWSECRET") {
		t.Errorf("late-added secret leaked: %q", out)
	}
}

func TestAddSecretAlreadyInBuffer(t *testing.T) {
	// Edge case: secret added while data containing it is in the buffer
	// This is tricky - data may have already been partially emitted
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 0)
	// Write without flushing - data is buffered
	w.Write([]byte("containsSECREThere"))
	// Now add the secret
	w.AddSecret("SECRET")
	// Flush - will the SECRET be caught?
	w.Flush()
	out := buf.String()
	// NOTE: This is a potential bug area - the secret might leak because
	// some bytes may have already been emitted before AddSecret was called
	// Let's see what actually happens
	t.Logf("AddSecretAlreadyInBuffer output: %q", out)
	// This test documents current behavior rather than asserting correctness
}

// =====================================================
// SPECIAL PATTERNS TESTS
// =====================================================

func TestSecretWithSpecialChars(t *testing.T) {
	// Secret with regex-special characters (but we're not using regex)
	secret := "pass.*word[123]"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "the "+secret+" is here")
	if strings.Contains(out, secret) {
		t.Errorf("special char secret leaked: %q", out)
	}
}

func TestSecretWithNewlines(t *testing.T) {
	// Secret containing newlines
	secret := "multi\nline\nsecret"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "start\n"+secret+"\nend")
	if strings.Contains(out, secret) {
		t.Errorf("multiline secret leaked: %q", out)
	}
}

func TestSecretWithNullBytes(t *testing.T) {
	// Secret containing null bytes
	secret := "null\x00secret"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "x"+secret+"y")
	if strings.Contains(out, secret) {
		t.Errorf("null byte secret leaked: %q", out)
	}
}

func TestSecretWithTabs(t *testing.T) {
	// Secret containing tabs
	secret := "tab\tsecret"
	var buf bytes.Buffer
	w := redact.New(&buf, []string{secret}, 0)
	out := collectString(w, &buf, "x"+secret+"y")
	if strings.Contains(out, secret) {
		t.Errorf("tab secret leaked: %q", out)
	}
}

// =====================================================
// BYTES WRITTEN TRACKING
// =====================================================

func TestBytesWrittenWithRedaction(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, []string{"xxx"}, 0)
	w.Write([]byte("axxx")) // "a" + "[REDACTED]" = 11 chars
	w.Flush()
	if w.BytesWritten() != 11 {
		t.Errorf("expected 11 bytes written, got %d", w.BytesWritten())
	}
}

func TestBytesWrittenWithMaxOutput(t *testing.T) {
	var buf bytes.Buffer
	w := redact.New(&buf, nil, 5)
	w.Write([]byte("hello world"))
	w.Flush()
	if w.BytesWritten() != 5 {
		t.Errorf("expected 5 bytes written, got %d", w.BytesWritten())
	}
}

// =====================================================
// HELPER
// =====================================================

func collectString(w *redact.Writer, buf *bytes.Buffer, input string) string {
	w.Write([]byte(input))
	w.Flush()
	return buf.String()
}
