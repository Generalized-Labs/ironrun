package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testRootForHints() *cobra.Command {
	root := &cobra.Command{Use: "ironrun"}
	for _, name := range []string{"run", "status", "doctor", "env", "init"} {
		root.AddCommand(&cobra.Command{Use: name, Run: func(*cobra.Command, []string) {}})
	}
	return root
}

func TestSuggestCommandFixesTypos(t *testing.T) {
	root := testRootForHints()
	if got := suggestCommand(root, "statuz"); got != "status" {
		t.Fatalf("suggestCommand(statuz) = %q, want status", got)
	}
	if got := suggestCommand(root, "rnu"); got != "run" {
		t.Fatalf("suggestCommand(rnu) = %q, want run", got)
	}
}

func TestSuggestCommandIgnoresFarMisses(t *testing.T) {
	root := testRootForHints()
	if got := suggestCommand(root, "frobnicate"); got != "" {
		t.Fatalf("suggestCommand(frobnicate) = %q, want empty", got)
	}
}

func TestUnknownCommandNameParsing(t *testing.T) {
	name, ok := unknownCommandName(`unknown command "statuz" for "ironrun"`)
	if !ok || name != "statuz" {
		t.Fatalf("got %q,%v want statuz,true", name, ok)
	}
	if _, ok := unknownCommandName("policy file not found"); ok {
		t.Fatal("non-unknown-command error parsed as unknown command")
	}
}

func TestErrorHintCoversTopOffenders(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"policy file not found: ironrun.yml", "ironrun init"},
		{"policy file malformed: bad", "ironrun validate"},
		{`command "x" not found in policy`, "ironrun validate"},
		{"no active environment is selected", "ironrun new NAME"},
		{`secret "K" not found in linux-backend`, "ironrun env set"},
		{"secret resolution failed: boom", "ironrun env set"},
		{"provider not configured", "ironrun doctor"},
		{"unknown flag: --bogus", "ironrun <command> --help"},
	}
	for _, tc := range cases {
		if got := errorHint(tc.msg); !strings.Contains(got, tc.want) {
			t.Fatalf("errorHint(%q) = %q, want it to contain %q", tc.msg, got, tc.want)
		}
	}
}

func TestErrorHintSkipsAlreadyRemediated(t *testing.T) {
	msg := "no active environment; run `ironrun new NAME` first"
	if got := errorHint(msg); got != "" {
		t.Fatalf("errorHint should skip messages with inline remediation, got %q", got)
	}
}
