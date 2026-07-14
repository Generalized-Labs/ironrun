package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The generated policy + agent instructions must reflect the project's REAL
// task-runner scripts (not hardcoded examples).
func TestInit_GeneratesPolicyFromScripts(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "demo",
  "scripts": {
    "dev": "vite",
    "test": "vitest",
    "build": "vite build",
    "seed": "node scripts/seed.js"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DATABASE_URL=postgres://x\nAPI_KEY=abc\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out, err := runInit(t, dir)
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(dir, "ironrun.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var pol struct {
		EnvironmentSet string `yaml:"environment_set"`
		Secrets        map[string]struct {
			Env   string   `yaml:"env"`
			Allow []string `yaml:"allow"`
		} `yaml:"secrets"`
		Commands []struct {
			ID      string   `yaml:"id"`
			Argv    []string `yaml:"argv"`
			Secrets []string `yaml:"secrets"`
		} `yaml:"commands"`
	}
	if err := yaml.Unmarshal(data, &pol); err != nil {
		t.Fatalf("generated policy is invalid YAML: %v\n%s", err, data)
	}
	argvByID := map[string][]string{}
	secretsByID := map[string][]string{}
	for _, c := range pol.Commands {
		argvByID[c.ID] = c.Argv
		secretsByID[c.ID] = c.Secrets
	}

	// A custom script becomes a real command.
	if got := argvByID["seed"]; len(got) != 3 || got[0] != "npm" || got[1] != "run" || got[2] != "seed" {
		t.Errorf("expected seed -> [npm run seed], got %v\npolicy:\n%s", got, data)
	}
	// Conventional `test` script -> `npm test`.
	if got := argvByID["test"]; len(got) != 2 || got[1] != "test" {
		t.Errorf("expected test -> [npm test], got %v", got)
	}
	// dev is credential-likely -> encrypted-vault aliases are bound.
	if pol.EnvironmentSet != "active" || pol.Secrets["DATABASE_URL"].Env != "DATABASE_URL" || !containsString(secretsByID["dev"], "DATABASE_URL") {
		t.Errorf("expected dev to carry DATABASE_URL vault alias, got %v\npolicy:\n%s", secretsByID["dev"], data)
	}

	// Agent instructions reference the REAL ids + the propose escape hatch.
	claude, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(claude), `run_sealed("seed")`) {
		t.Errorf("CLAUDE.md should reference run_sealed(\"seed\"); got:\n%s", claude)
	}
	if !strings.Contains(string(claude), "propose_command") {
		t.Errorf("CLAUDE.md should mention propose_command")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
