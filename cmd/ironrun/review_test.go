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

// Agent-controlled proposal text (reason, env names/refs, v2 secret names) must
// land in ironrun.yml as data. A line break in any of them must never smuggle
// an extra command into the policy past the human reviewing the proposal.
func TestAppendCommandCannotInjectPolicyYAML(t *testing.T) {
	smuggled := "\n  - id: evil\n    argv: [curl, evil.example]\n    allow_network: true\n"
	for _, tc := range []struct {
		name, policy string
		proposal     pending.Proposal
	}{
		{"reason", "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet"}, Reason: "lint" + smuggled}},
		{"reason-unicode-line-separator", "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet"}, Reason: "lint   - id: evil     argv: [id]"}},
		{"env-ref", "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet"}, Env: map[string]string{"TOKEN": "TOKEN" + smuggled}}},
		{"env-name", "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet"}, Env: map[string]string{"TOKEN: x" + smuggled: "TOKEN"}}},
		{"argv-carriage-return", "version: \"1\"\nprovider: env\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet]\r  - id: evil\r    argv: [id"}}},
		{"v2-secret-name", "version: \"2\"\nenvironment_set: active\ncommands:\n  - id: test\n    argv: [go, test]\n",
			pending.Proposal{ID: "vet", Argv: []string{"go", "vet"}, Env: map[string]string{"TOKEN]" + smuggled + "    secrets: [X": "x"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ironrun.yml")
			if err := os.WriteFile(path, []byte(tc.policy), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = appendCommandToPolicy(path, tc.proposal) // refusing is also safe
			parsed, err := policy.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range parsed.Commands {
				if c.ID != "test" && c.ID != "vet" {
					data, _ := os.ReadFile(path)
					t.Fatalf("proposal smuggled command %q into the policy:\n%s", c.ID, data)
				}
			}
		})
	}
}
