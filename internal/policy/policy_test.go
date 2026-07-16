package policy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

const validPolicy = `
version: "1"
provider: env
commands:
  - id: test
    argv: [go, test, ./...]
    ttl: 5m
    max_bytes: 1048576
  - id: build
    argv: [go, build, ./cmd/ironrun]
    env:
      CGO_ENABLED: "0"
`

func TestParse_Valid(t *testing.T) {
	f, err := policy.Parse([]byte(validPolicy))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Commands) != 2 {
		t.Errorf("expected 2 commands, got %d", len(f.Commands))
	}
}

func TestParse_FileSecretValidation(t *testing.T) {
	valid := `version: "1"
provider: env
secrets:
  google:
    env: GOOGLE_APPLICATION_CREDENTIALS
    kind: file
    filename: service-account.json
    allow: [test]
commands:
  - id: test
    argv: [go, test, ./...]
    secrets: [google]
`
	f, err := policy.Parse([]byte(valid))
	if err != nil || f.Secrets["google"].EffectiveKind() != "file" {
		t.Fatalf("file policy = %#v, %v", f, err)
	}
	invalid := strings.Replace(valid, "service-account.json", "../secret.json", 1)
	if _, err := policy.Parse([]byte(invalid)); !errors.Is(err, policy.ErrMalformed) {
		t.Fatalf("traversal error = %v", err)
	}
}

func TestParse_MissingVersion(t *testing.T) {
	yaml := `
provider: env
commands:
  - id: test
    argv: [go, test]
`
	_, err := policy.Parse([]byte(yaml))
	if !errors.Is(err, policy.ErrBadVersion) {
		t.Errorf("expected ErrBadVersion, got %v", err)
	}
}

func TestParse_Malformed(t *testing.T) {
	_, err := policy.Parse([]byte("not: valid: yaml: ["))
	if !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestParse_Empty(t *testing.T) {
	yaml := `version: "1"
provider: env
commands: []
`
	_, err := policy.Parse([]byte(yaml))
	if !errors.Is(err, policy.ErrNoCommands) {
		t.Errorf("expected ErrNoCommands, got %v", err)
	}
}

func TestParse_MissingID(t *testing.T) {
	yaml := `version: "1"
provider: env
commands:
  - argv: [go, test]
`
	_, err := policy.Parse([]byte(yaml))
	if !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestParse_DuplicateID(t *testing.T) {
	yaml := `version: "1"
provider: env
commands:
  - id: test
    argv: [go, test]
  - id: test
    argv: [go, build]
`
	_, err := policy.Parse([]byte(yaml))
	if !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("expected ErrMalformed, got %v", err)
	}
}

func TestLookup(t *testing.T) {
	f, _ := policy.Parse([]byte(validPolicy))
	cmd, err := f.Lookup("test")
	if err != nil || cmd.ID != "test" {
		t.Errorf("unexpected result: cmd=%v err=%v", cmd, err)
	}
	_, err = f.Lookup("missing")
	if err == nil {
		t.Error("expected error for missing command")
	}
}

func TestAuthorizeArgv(t *testing.T) {
	f, _ := policy.Parse([]byte(validPolicy))
	cmd, _ := f.Lookup("test")

	if err := policy.AuthorizeArgv(cmd, []string{"go", "test", "./..."}); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
	if err := policy.AuthorizeArgv(cmd, []string{"go", "test"}); err == nil {
		t.Error("expected argv mismatch error")
	}
	if err := policy.AuthorizeArgv(cmd, []string{"go", "test", "./...", "--extra"}); err == nil {
		t.Error("expected argv mismatch error")
	}
}

func TestIsShellString(t *testing.T) {
	shells := [][]string{
		{"sh", "-c", "echo $SECRET"},
		{"bash", "-c", "env"},
		{"/bin/sh", "-c", "printenv"},
	}
	for _, s := range shells {
		if !policy.IsShellString(s) {
			t.Errorf("expected shell string: %v", s)
		}
	}
	if policy.IsShellString([]string{"go", "test"}) {
		t.Error("go test should not be detected as shell")
	}
}

func TestLoad_NotFound(t *testing.T) {
	_, err := policy.Load("/tmp/does-not-exist-ironrun.yml")
	if !errors.Is(err, policy.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestParse_TTLDuration(t *testing.T) {
	yaml := `version: "1"
provider: env
commands:
  - id: slow
    argv: [sleep, 10]
    ttl: 30s
`
	f, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if f.Commands[0].TTL.Seconds() != 30 {
		t.Errorf("expected 30s TTL, got %v", f.Commands[0].TTL)
	}
}

func TestParse_BadTTL(t *testing.T) {
	yaml := `version: "1"
provider: env
commands:
  - id: bad
    argv: [go, test]
    ttl: notaduration
`
	_, err := policy.Parse([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "duration") {
		t.Errorf("expected duration error, got %v", err)
	}
}

func TestParse_SecretBindingsAreExplicit(t *testing.T) {
	yaml := `version: "1"
provider: env
secrets:
  api:
    env: API_KEY
    allow: [test]
commands:
  - id: test
    argv: [go, test]
    secrets: [api]
`
	f, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if f.Secrets["api"].Env != "API_KEY" {
		t.Fatalf("secret env binding not loaded")
	}
}

func TestParse_SecretCannotWidenAccess(t *testing.T) {
	yaml := `version: "1"
provider: env
secrets:
  api:
    env: API_KEY
    allow: [other]
commands:
  - id: test
    argv: [go, test]
    secrets: [api]
`
	if _, err := policy.Parse([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected explicit allow failure, got %v", err)
	}
}

func TestParse_V2UsesDirectEnvironmentEntryNames(t *testing.T) {
	yaml := `version: "2"
require_agent_leases: true
commands:
  - id: benchmark
    argv: [python3, scripts/benchmark.py]
    secrets: [OPENROUTER_API_KEY, service-account.json]
`
	f, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if !f.UsesEnvironmentEntries() || len(f.Secrets) != 0 {
		t.Fatalf("v2 policy did not use direct entries: %#v", f)
	}
}

func TestParse_V2RejectsInvalidAndDuplicateEntryNames(t *testing.T) {
	invalid := `version: "2"
commands:
  - id: test
    argv: [go, test]
    secrets: [../API_KEY]
`
	if _, err := policy.Parse([]byte(invalid)); !errors.Is(err, policy.ErrMalformed) {
		t.Fatalf("invalid direct entry error = %v", err)
	}
	duplicate := strings.Replace(invalid, "../API_KEY", "API_KEY, API_KEY", 1)
	if _, err := policy.Parse([]byte(duplicate)); !errors.Is(err, policy.ErrMalformed) {
		t.Fatalf("duplicate direct entry error = %v", err)
	}
}
