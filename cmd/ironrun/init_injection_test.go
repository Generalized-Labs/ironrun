package main

import (
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

// A repository's package.json is untrusted input to `ironrun setup`: a script
// name lands in the generated command's argv and comment, and a line break in
// it must not be able to add fields or commands to the policy the user
// believes they generated (2026-10 audit).
func TestGeneratePolicyNotInjectableByScriptName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"scripts":{"test":"vitest","zz\n    allow_network: true\n  - id: evil\n    argv: [id]":"x"}}`)
	cmds := detectCommands(dir, nil)
	crafted := false
	for _, c := range cmds {
		if len(c.Argv) == 3 && strings.Contains(c.Argv[2], "allow_network") {
			crafted = true
		}
	}
	if !crafted {
		t.Fatal("crafted script was not detected; the test would be vacuous")
	}
	f, err := policy.Parse([]byte(generatePolicy(cmds, []string{"API_KEY"})))
	if err != nil {
		t.Fatalf("generated policy does not parse: %v", err)
	}
	for _, c := range f.Commands {
		if c.ID == "evil" || c.AllowNetwork {
			t.Fatalf("script name reshaped the generated policy: %+v", c)
		}
	}
}
