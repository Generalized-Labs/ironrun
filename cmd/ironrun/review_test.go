package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/pending"
	"github.com/generalized-labs/ironrun/internal/policy"
)

func TestAppendCommandInsertsBeforeFollowingTopLevelFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ironrun.yml")
	original := "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test, ./...]\n\n# workspace selector\nenvironment_set: active\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	proposal := pending.Proposal{ID: "vet", Argv: []string{"go", "vet", "./..."}, Reason: "acceptance"}
	if err := appendCommandToPolicy(path, proposal); err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Lookup("vet"); err != nil || parsed.EnvironmentSet != "active" {
		t.Fatalf("approved policy = %#v, %v", parsed, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(data), "id: vet") > strings.Index(string(data), "environment_set:") {
		t.Fatal("approved command was not inserted inside commands sequence")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("policy mode = %v, %v", info.Mode().Perm(), err)
	}
}
