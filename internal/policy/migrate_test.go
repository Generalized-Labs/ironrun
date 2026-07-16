package policy_test

import (
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

func TestMigrateV1ToV2PreservesCommentsAndRebindsEntries(t *testing.T) {
	input := `# owner review stays here
version: "1"
provider: passthrough
secrets:
  openrouter: # alias comment
    env: OPENROUTER_API_KEY
    store: envfile
    allow: [benchmark]
commands:
  # exact benchmark command
  - id: benchmark
    argv: [python3, benchmark.py]
    secrets: [openrouter]
`
	out, mapping, err := policy.MigrateV1ToV2([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{"# owner review stays here", "# exact benchmark command", `version: "2"`, "secrets: [OPENROUTER_API_KEY]", `environment_set: active`} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration lost %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "openrouter: # alias comment") || mapping["openrouter"] != "OPENROUTER_API_KEY" {
		t.Fatalf("legacy alias was not removed: %v\n%s", mapping, text)
	}
}

func TestMigrateV1ToV2RejectsAmbiguousTargets(t *testing.T) {
	input := `version: "1"
provider: passthrough
secrets:
  first: {env: API_KEY, allow: [test]}
  second: {env: API_KEY, allow: [test]}
commands:
  - id: test
    argv: [go, test]
    secrets: [first, second]
`
	if _, _, err := policy.MigrateV1ToV2([]byte(input)); err == nil || !strings.Contains(err.Error(), "both target") {
		t.Fatalf("expected ambiguous target rejection, got %v", err)
	}
}
