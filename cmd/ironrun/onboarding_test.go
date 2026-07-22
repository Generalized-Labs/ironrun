package main

import (
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
