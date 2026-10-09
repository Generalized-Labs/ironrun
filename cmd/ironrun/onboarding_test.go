package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

func TestGeneratePolicyUsesEncryptedLocalVault(t *testing.T) {
	content := generatePolicy([]DetectedCmd{{
		ID: "build", Argv: []string{"go", "build", "./..."}, TTL: "2m", NeedsEnv: true,
	}}, []string{"OPENAI_API_KEY"})
	parsed, err := policy.Parse([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EnvironmentSet != "active" || !parsed.RequireAgentLeases {
		t.Fatalf("generated policy is not local-vault-first: %#v", parsed)
	}
	if parsed.Version != policy.SupportedVersionV2 || len(parsed.Secrets) != 0 {
		t.Fatalf("generated policy should use direct v2 environment entries: %#v", parsed)
	}
	if len(parsed.Commands) != 1 || len(parsed.Commands[0].Secrets) != 1 || parsed.Commands[0].Secrets[0] != "OPENAI_API_KEY" {
		t.Fatalf("generated command bindings = %#v", parsed.Commands)
	}
}

// REGRESSION: `export API_KEY=...` was detected as the key "export API_KEY",
// and the generated policy then failed to load at all.
func TestDetectEnvVarsStripsExport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("export API_KEY=TEST-SECRET-0000\nDATABASE_URL=TEST-SECRET-0001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := detectEnvVars(dir)
	if strings.Join(vars, ",") != "API_KEY,DATABASE_URL" {
		t.Fatalf("detected %q", vars)
	}
	content := generatePolicy([]DetectedCmd{{ID: "test", Argv: []string{"go", "test"}, NeedsEnv: true}}, vars)
	if _, err := policy.Parse([]byte(content)); err != nil {
		t.Fatalf("generated policy does not load: %v\n%s", err, content)
	}
}

func TestGeneratePolicyEmptyProjectIsImmediatelyValid(t *testing.T) {
	content := generatePolicy(nil, nil)
	parsed, err := policy.Parse([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Commands) != 1 || parsed.Commands[0].ID != "ironrun-health" {
		t.Fatalf("starter command = %#v", parsed.Commands)
	}
	if strings.Contains(content, "    env:") || strings.Contains(content, "    secrets:") {
		t.Fatalf("empty project policy invented secrets:\n%s", content)
	}
}

func TestRenderAgentInstructionsUsesMCPCommandIDShape(t *testing.T) {
	instructions := renderAgentInstructions([]DetectedCmd{{
		ID: "test", Comment: "go test ./...",
	}})
	if !strings.Contains(instructions, `run_sealed({command_id: "test"})`) {
		t.Fatalf("strict command instructions must use the MCP command_id argument:\n%s", instructions)
	}
	if strings.Contains(instructions, `run_sealed("test")`) {
		t.Fatalf("instructions use an unsupported positional run_sealed call:\n%s", instructions)
	}
}
