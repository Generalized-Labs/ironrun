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
	secret, ok := parsed.Secrets["OPENAI_API_KEY"]
	if !ok || secret.Env != "OPENAI_API_KEY" || len(secret.Allow) != 1 || secret.Allow[0] != "build" {
		t.Fatalf("generated secret declaration = %#v", secret)
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
	if strings.Contains(content, "env:") || strings.Contains(content, "secrets:") {
		t.Fatalf("empty project policy invented secrets:\n%s", content)
	}
}
