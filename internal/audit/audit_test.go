package audit

import (
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
	t.Run("off disables", func(t *testing.T) {
		t.Setenv("IRONRUN_AUDIT_LOG", "off")
		if got := ResolvePath("/some/policy/path"); got != "" {
			t.Errorf("expected disabled (empty), got %q", got)
		}
	})
	t.Run("env wins over policy", func(t *testing.T) {
		t.Setenv("IRONRUN_AUDIT_LOG", "/env/path.log")
		if got := ResolvePath("/policy/path.log"); got != "/env/path.log" {
			t.Errorf("env should win, got %q", got)
		}
	})
	t.Run("policy field used when no env", func(t *testing.T) {
		os.Unsetenv("IRONRUN_AUDIT_LOG")
		if got := ResolvePath("/policy/path.log"); got != "/policy/path.log" {
			t.Errorf("expected policy path, got %q", got)
		}
	})
}
