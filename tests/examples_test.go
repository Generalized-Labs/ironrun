package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

// TestExamplePoliciesParse ensures every example policy in examples/ is a valid
// ironrun policy, so the published examples can't bit-rot.
func TestExamplePoliciesParse(t *testing.T) {
	dir := filepath.Join("..", "examples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("could not read examples dir: %v", err)
	}

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") {
			continue
		}
		// ci-github-action.yml is a GitHub Actions workflow, not a policy.
		if name == "ci-github-action.yml" {
			continue
		}
		f, err := policy.Load(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: failed to parse as a policy: %v", name, err)
			continue
		}
		if len(f.Commands) == 0 {
			t.Errorf("%s: has no commands", name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no example policies found to check")
	}
}
