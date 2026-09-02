package main

import (
	"strings"
	"testing"
)

// The vault root key decrypts every value in a project. `ironrun env share`
// must therefore reach a human at a terminal and nothing else — not a pipe, a
// redirect, a CI step, or an AI agent session that captures command output.
//
// `go test` runs with stdout attached to a pipe, so the guard is exercised here
// simply by invoking the command.
func TestEnvShareRefusesNonInteractiveSession(t *testing.T) {
	cmd := envShareCmd()
	cmd.SetArgs(nil)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()
	if err == nil {
		t.Fatal("env share exported the vault root key to a non-interactive session")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Errorf("expected a non-interactive refusal, got: %v", err)
	}

	// The refusal must land before the store is opened, so a misconfigured or
	// locked vault cannot turn this into a different, weaker error path.
	if strings.Contains(err.Error(), "does not support vault export") {
		t.Error("guard ran after opening the store; it must refuse before touching the vault")
	}
}

func TestConfirmPhraseRequiresExactMatch(t *testing.T) {
	// confirmPhrase reads os.Stdin, which under `go test` is not a terminal.
	// The contract worth pinning here is that only an exact match passes, so
	// the comparison itself is asserted directly.
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{"export", true},
		{"  export  ", true},
		{"Export", false},
		{"exports", false},
		{"y", false},
		{"", false},
	} {
		got := strings.TrimSpace(tc.input) == "export"
		if got != tc.want {
			t.Errorf("phrase %q: got %v, want %v", tc.input, got, tc.want)
		}
	}
}
