package audit_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/generalized-labs/ironrun/internal/audit"
)

func TestLog_WritesJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("IRONRUN_AUDIT_PATH", path)
	t.Setenv("IRONRUN_AUDIT", "")

	audit.Log(audit.Record{Event: "run_sealed", CommandID: "test", ExitCode: 0, Redactions: 2})
	audit.Log(audit.Record{Event: "run_sealed", CommandID: "build", ExitCode: 1})

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("invalid JSONL line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].CommandID != "test" || recs[0].Redactions != 2 {
		t.Errorf("unexpected first record: %+v", recs[0])
	}
}

func TestLog_DisabledByEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("IRONRUN_AUDIT_PATH", path)
	t.Setenv("IRONRUN_AUDIT", "off")
	audit.Log(audit.Record{CommandID: "x"})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("audit file must not exist when IRONRUN_AUDIT=off")
	}
}

func TestHashArgv_StableAndDistinct(t *testing.T) {
	a := audit.HashArgv([]string{"go", "test", "./..."})
	b := audit.HashArgv([]string{"go", "test", "./..."})
	c := audit.HashArgv([]string{"go", "build"})
	if a != b {
		t.Errorf("hash not stable: %q != %q", a, b)
	}
	if a == c {
		t.Errorf("hash not distinct for different argv")
	}
	if len(a) != 16 {
		t.Errorf("expected 16-char hash, got %d (%q)", len(a), a)
	}
}

func TestLog_Rotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("IRONRUN_AUDIT_PATH", path)
	t.Setenv("IRONRUN_AUDIT", "")
	t.Setenv("IRONRUN_AUDIT_MAX_BYTES", "120")
	for i := 0; i < 20; i++ {
		audit.Log(audit.Record{Event: "run_sealed", CommandID: "cmd", ArgvHash: "abcdef0123456789"})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotated file %s.1 to exist: %v", path, err)
	}
}
