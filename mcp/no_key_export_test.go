package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The project vault root key decrypts every value in the project. Exposing it
// through MCP would hand an agent the master key in a single ungated call, and
// the value would persist in the agent transcript — the exact disclosure
// Ironrun exists to prevent. No approval gate makes that safe, so the key must
// stay off the MCP surface entirely. Humans use `ironrun env share` instead.
//
// This guard fails if key export or a vault path leak is reintroduced here.
func TestMCPSurfaceNeverExportsVaultKey(t *testing.T) {
	banned := []string{
		"ExportRootKey",
		"share_environment",
		"sync_environment",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		// Skip this guard, which necessarily names the banned symbols.
		if name == "no_key_export_test.go" {
			continue
		}

		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, symbol := range banned {
			if strings.Contains(string(src), symbol) {
				t.Errorf("%s references %q: the vault root key and remote sync must not be reachable over MCP (see SECURITY.md)", name, symbol)
			}
		}
	}
}
