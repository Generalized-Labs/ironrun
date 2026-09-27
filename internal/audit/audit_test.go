package audit

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempLog(t *testing.T) (string, *Logger) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return path, l
}

func TestAppendAndVerify_Intact(t *testing.T) {
	path, l := tempLog(t)
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{CommandID: "c", Argv: []string{"echo"}, ExitCode: i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	broken, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if broken != -1 {
		t.Fatalf("expected intact (-1), got broken line %d", broken)
	}
}

func TestVerify_DetectsTamper(t *testing.T) {
	path, l := tempLog(t)
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{CommandID: "c", Argv: []string{"echo"}, ExitCode: i}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	// Tamper with the second record's exit_code (without recomputing its hash).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 records, got %d", len(lines))
	}
	lines[1] = strings.Replace(lines[1], `"exit_code":1`, `"exit_code":99`, 1)
	if !strings.Contains(lines[1], `"exit_code":99`) {
		t.Fatalf("setup: did not rewrite exit_code in line 2: %s", lines[1])
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	broken, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if broken != 2 {
		t.Fatalf("expected tamper detected at line 2, got %d", broken)
	}
}

func TestAppend_GenesisLink(t *testing.T) {
	path, l := tempLog(t)
	if err := l.Append(Entry{CommandID: "c", Argv: []string{"echo"}}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"prev_hash":"`+genesisHash+`"`) {
		t.Errorf("first entry should link to genesis hash, got: %s", data)
	}
}

func TestNilLogger_NoOp(t *testing.T) {
	var l *Logger
	if err := l.Append(Entry{}); err != nil {
		t.Errorf("nil Append should be a no-op, got %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("nil Close should be a no-op, got %v", err)
	}
}

func TestResolvePath(t *testing.T) {
	t.Run("env off no longer disables", func(t *testing.T) {
		// ResolvePath's return value is env-independent now, so compute the
		// expectation first and require it to be stable with the env set.
		want := ResolvePath("/policy/path.log")
		t.Setenv("IRONRUN_AUDIT_LOG", "off")
		if got := ResolvePath("/policy/path.log"); got != want {
			t.Errorf("env IRONRUN_AUDIT_LOG=off must be ignored, got %q want %q", got, want)
		}
	})
	t.Run("env path no longer wins over policy", func(t *testing.T) {
		t.Setenv("IRONRUN_AUDIT_LOG", "/env/path.log")
		if got := ResolvePath("/policy/path.log"); got != "/policy/path.log" {
			t.Errorf("env should be ignored, policy field should win, got %q", got)
		}
	})
	t.Run("policy field used when no env", func(t *testing.T) {
		os.Unsetenv("IRONRUN_AUDIT_LOG")
		if got := ResolvePath("/policy/path.log"); got != "/policy/path.log" {
			t.Errorf("expected policy path, got %q", got)
		}
	})
	t.Run("env set warns loudly on stderr", func(t *testing.T) {
		t.Setenv("IRONRUN_AUDIT_LOG", "/env/path.log")
		stderr := captureStderr(t, func() {
			ResolvePath("/policy/path.log")
		})
		if !strings.Contains(stderr, "SECURITY WARNING") || !strings.Contains(stderr, "IRONRUN_AUDIT_LOG") {
			t.Errorf("expected loud SECURITY WARNING about IRONRUN_AUDIT_LOG on stderr, got %q", stderr)
		}
	})
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what
// was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestOpen_VerifyOnOpen_IntactLog opens an existing intact log: no error, and
// appending continues the chain.
func TestOpen_VerifyOnOpen_IntactLog(t *testing.T) {
	path, l := tempLog(t)
	if err := l.Append(Entry{CommandID: "a", Argv: []string{"echo", "hi"}}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("Open on intact log: %v", err)
	}
	defer l2.Close()
	if err := l2.Append(Entry{CommandID: "b", Argv: []string{"echo", "yo"}}); err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}
	if broken, err := Verify(path); err != nil || broken != -1 {
		t.Fatalf("chain should be intact after reopen+append, broken=%d err=%v", broken, err)
	}
}

// TestOpen_VerifyOnOpen_TamperDetected: a tampered log must fail LOUDLY at
// open time — an error naming the tamper — not be silently appended to.
func TestOpen_VerifyOnOpen_TamperDetected(t *testing.T) {
	path, l := tempLog(t)
	for i := 0; i < 2; i++ {
		if err := l.Append(Entry{CommandID: "c", Argv: []string{"echo"}, ExitCode: i}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"exit_code":1`, `"exit_code":99`, 1)
	if tampered == string(data) {
		t.Fatal("setup: could not rewrite exit_code")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(path)
	if err == nil {
		t.Fatal("Open on tampered log should fail loudly, got nil error")
	}
	if !strings.Contains(err.Error(), "TAMPER DETECTED") {
		t.Errorf("tamper error should say TAMPER DETECTED, got: %v", err)
	}
	if !strings.Contains(err.Error(), "record 2") {
		t.Errorf("tamper error should name the broken record, got: %v", err)
	}
}

// TestAppend_ScrubsSecretValuesFromArgv: exact secret values AND their encoded
// variants must never land in the stored record; everything else stays.
func TestAppend_ScrubsSecretValuesFromArgv(t *testing.T) {
	path, l := tempLog(t)
	secret := "s3cr3t-value-12345"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))

	argv := []string{
		"curl",
		"-H", "Authorization: Bearer " + secret, // exact value embedded
		"--data", "token=" + b64, // base64 variant embedded
		"https://example.com/api",
	}
	entry := Entry{
		CommandID:   "c",
		Argv:        argv,
		SecretNames: []string{"API_TOKEN"},
		ScrubValues: []string{secret},
	}
	if err := l.Append(entry); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// The caller's slice must be untouched by the scrub.
	if !strings.Contains(argv[2], secret) {
		t.Error("scrub must not mutate the caller's argv slice")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(data)
	for _, leak := range []string{secret, b64} {
		if strings.Contains(logged, leak) {
			t.Errorf("secret material leaked into audit log: %q", leak)
		}
	}
	if !strings.Contains(logged, "[REDACTED]") {
		t.Error("expected scrubbed argv to contain the [REDACTED] placeholder")
	}
	for _, want := range []string{`"curl"`, "https://example.com/api"} {
		if !strings.Contains(logged, want) {
			t.Errorf("non-secret argv %q should be preserved, got: %s", want, logged)
		}
	}
	if strings.Contains(logged, "ScrubValues") || strings.Contains(logged, "scrub_values") {
		t.Error("ScrubValues must never be serialized into the record")
	}
	if broken, err := Verify(path); err != nil || broken != -1 {
		t.Fatalf("chain should be intact after scrubbed append, broken=%d err=%v", broken, err)
	}
}

// TestAppend_ScrubSkipsShortValues documents the floor: values shorter than
// 4 bytes are not exact-matched (mirrors the runner's minRedactableSecretLen),
// because scrubbing 1-3 byte tokens would mangle ordinary argv.
func TestAppend_ScrubSkipsShortValues(t *testing.T) {
	path, l := tempLog(t)
	if err := l.Append(Entry{
		CommandID:   "c",
		Argv:        []string{"echo", "abc"},
		ScrubValues: []string{"abc"},
	}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"echo","abc"`) {
		t.Errorf("short values must be left alone, got: %s", data)
	}
}

// TestVerify_OldFormatRecordStillVerifies: records written before the
// seccomp_installed/seccomp_detail fields existed (zero new fields serialize
// to nothing via omitempty) must keep verifying after the upgrade.
func TestVerify_OldFormatRecordStillVerifies(t *testing.T) {
	path, l := tempLog(t)
	for i := 0; i < 2; i++ {
		// Zero new fields: the written line is byte-identical to a pre-0.6 record.
		if err := l.Append(Entry{CommandID: "c", Argv: []string{"echo"}, ExitCode: i}); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "seccomp_installed") {
		t.Errorf("zero new fields must serialize to nothing (old-format compat), got: %s", data)
	}
	if broken, err := Verify(path); err != nil || broken != -1 {
		t.Fatalf("old-format records must still verify, broken=%d err=%v", broken, err)
	}
}

// TestAppend_SeccompInstalledRecorded: the installed flag and detail round-trip
// through the record; a false value stays absent (old-format compat).
func TestAppend_SeccompInstalledRecorded(t *testing.T) {
	path, l := tempLog(t)
	if err := l.Append(Entry{
		CommandID:        "c",
		Argv:             []string{"true"},
		SeccompRequested: true,
		SeccompInstalled: true,
		SeccompDetail:    "filter installed via sealed-exec shim",
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{CommandID: "d", Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 records, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"seccomp_installed":true`) {
		t.Errorf("record 1 should carry seccomp_installed:true, got: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"seccomp_detail":"filter installed via sealed-exec shim"`) {
		t.Errorf("record 1 should carry seccomp_detail, got: %s", lines[0])
	}
	if strings.Contains(lines[1], "seccomp_installed") {
		t.Errorf("false seccomp_installed must stay absent, got: %s", lines[1])
	}
	if broken, err := Verify(path); err != nil || broken != -1 {
		t.Fatalf("chain should be intact, broken=%d err=%v", broken, err)
	}
}
