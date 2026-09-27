package scrub

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canaryA = "sk-canary-abc123XYZ789qrs" // synthetic test value, not a real secret

func TestVariantsCoversEncodings(t *testing.T) {
	v := Variants(canaryA)
	has := map[string]bool{}
	for _, x := range v {
		has[x] = true
	}
	if !has[canaryA] {
		t.Fatal("variants missing the exact value")
	}
	if !has[base64.StdEncoding.EncodeToString([]byte(canaryA))] {
		t.Fatal("variants missing base64")
	}
	if !has[base64.RawURLEncoding.EncodeToString([]byte(canaryA))] {
		t.Fatal("variants missing raw base64url")
	}
	// percent-encoding: '-' is unreserved, so craft a value that changes.
	w := "tok en/1+x"
	pv := Variants(w)
	found := false
	for _, x := range pv {
		if strings.Contains(x, "%20") || strings.Contains(x, "%2f") || strings.Contains(x, "%2F") {
			found = true
		}
	}
	if !found {
		t.Fatalf("variants missing percent-encoded form: %q", pv)
	}
	// lowercase hex variant present too
	foundLo := false
	for _, x := range pv {
		if strings.Contains(x, "%2b") {
			foundLo = true
		}
	}
	if !foundLo {
		t.Fatalf("variants missing lowercase percent-hex: %q", pv)
	}
}

func TestRedactExactAndVariants(t *testing.T) {
	secret := Secret{Alias: "TEST_API_KEY", Value: canaryA}
	m := NewMatcher([]Secret{secret})
	b64 := base64.StdEncoding.EncodeToString([]byte(canaryA))
	in := "before " + canaryA + " middle " + b64 + " after"
	got, n := m.Redact(in)
	if n != 2 {
		t.Fatalf("expected 2 replacements, got %d: %q", n, got)
	}
	if strings.Contains(got, canaryA) || strings.Contains(got, b64) {
		t.Fatalf("value leaked through redact: %q", got)
	}
	want := "[REDACTED:TEST_API_KEY:" + Sha8(canaryA) + "]"
	if strings.Count(got, want) != 2 {
		t.Fatalf("expected placeholder %q twice, got %q", want, got)
	}
}

func TestRedactIdempotent(t *testing.T) {
	m := NewMatcher([]Secret{{Alias: "K", Value: canaryA}})
	once, n1 := m.Redact("x " + canaryA + " y")
	twice, n2 := m.Redact(once)
	if n1 != 1 || n2 != 0 {
		t.Fatalf("idempotency broken: n1=%d n2=%d", n1, n2)
	}
	if once != twice {
		t.Fatalf("second redact changed text: %q -> %q", once, twice)
	}
}

func TestShortValuesSkipped(t *testing.T) {
	m := NewMatcher([]Secret{
		{Alias: "TINY", Value: "abc"},
		{Alias: "OK", Value: canaryA},
	})
	if m.Skipped() != 1 {
		t.Fatalf("expected 1 skipped alias, got %d", m.Skipped())
	}
	got, n := m.Redact("abc " + canaryA)
	if n != 1 || strings.Contains(got, canaryA) {
		t.Fatalf("unexpected redact result: %q (%d)", got, n)
	}
	if !strings.Contains(got, "abc ") {
		t.Fatalf("short value should be left alone: %q", got)
	}
}

func TestLongestMatchWins(t *testing.T) {
	// A value that is a prefix of another secret's value: longest must win.
	m := NewMatcher([]Secret{
		{Alias: "SHORT", Value: "prefix-12345678"},
		{Alias: "LONG", Value: "prefix-12345678-suffix-9999"},
	})
	got, n := m.Redact("v=prefix-12345678-suffix-9999!")
	if n != 1 {
		t.Fatalf("expected 1 replacement, got %d: %q", n, got)
	}
	if !strings.Contains(got, "[REDACTED:LONG:") {
		t.Fatalf("longest match did not win: %q", got)
	}
}

func TestSha8Stable(t *testing.T) {
	if Sha8(canaryA) != Sha8(canaryA) || len(Sha8(canaryA)) != 8 {
		t.Fatal("sha8 not stable/8-hex")
	}
	if Sha8(canaryA) == Sha8(canaryA+"x") {
		t.Fatal("sha8 collision on distinct values")
	}
}

func TestScrubWalkApplyAndIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home) // os.UserHomeDir follows $HOME on linux
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	claude := filepath.Join(home, ".claude", "projects", "proj")
	if err := os.MkdirAll(claude, 0o755); err != nil {
		t.Fatal(err)
	}
	dirty := filepath.Join(claude, "sess-1.jsonl")
	clean := filepath.Join(claude, "sess-2.jsonl")
	bin := filepath.Join(claude, "state.vscdb")
	if err := os.WriteFile(dirty, []byte(`{"out":"token `+canaryA+` here"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clean, []byte(`{"out":"nothing here"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("sqlite-binary\x00blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file OUTSIDE the six roots must never be touched.
	outside := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(outside, []byte("my key is "+canaryA), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewMatcher([]Secret{{Alias: "CANARY", Value: canaryA}})

	// Dry-run: report matches, change nothing.
	res, err := Scrub(m, KnownRoots(), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 1 {
		t.Fatalf("dry-run: expected 1 matched file, got %d", res.Matched)
	}
	raw, _ := os.ReadFile(dirty)
	if !strings.Contains(string(raw), canaryA) {
		t.Fatal("dry-run modified the file")
	}

	// Apply: rewrite atomically, preserve mode.
	res, err = Scrub(m, KnownRoots(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rewrote != 1 {
		t.Fatalf("apply: expected 1 rewrite, got %d", res.Rewrote)
	}
	raw, _ = os.ReadFile(dirty)
	if strings.Contains(string(raw), canaryA) {
		t.Fatalf("apply: value still present: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED:CANARY:"+Sha8(canaryA)+"]") {
		t.Fatalf("apply: placeholder missing: %s", raw)
	}
	st, _ := os.Stat(dirty)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("apply: mode not preserved: %v", st.Mode())
	}
	// Outside file untouched; sqlite skipped, not rewritten.
	raw, _ = os.ReadFile(outside)
	if !strings.Contains(string(raw), canaryA) {
		t.Fatal("file outside store roots was touched")
	}
	raw, _ = os.ReadFile(bin)
	if !strings.Contains(string(raw), "sqlite-binary") {
		t.Fatal("binary store file was modified")
	}

	// Second apply: idempotent, zero matches, zero rewrites.
	res, err = Scrub(m, KnownRoots(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 0 || res.Rewrote != 0 {
		t.Fatalf("not idempotent: matched=%d rewrote=%d", res.Matched, res.Rewrote)
	}
}

func TestScrubSkipsSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	sess := filepath.Join(home, ".codex", "sessions", "2026", "01", "02")
	if err := os.MkdirAll(sess, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "secret-target.txt")
	if err := os.WriteFile(target, []byte("leak "+canaryA), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(sess, "link.jsonl")); err != nil {
		t.Fatal(err)
	}
	m := NewMatcher([]Secret{{Alias: "C", Value: canaryA}})
	res, err := Scrub(m, KnownRoots(), true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(target)
	if !strings.Contains(string(raw), canaryA) {
		t.Fatal("symlink target outside/inside root was followed and rewritten")
	}
	found := false
	for _, f := range res.Files {
		if f.Skipped && strings.Contains(f.SkipReason, "symlink") {
			found = true
		}
	}
	if !found {
		t.Fatal("symlink not reported as skipped")
	}
}
