// Key-material guard for the MCP tool registry (Phase 0, item 0.1).
//
// A prior audit found that the share_environment MCP tool returned the vault
// root key to the agent with no approval gate — a direct violation of
// SECURITY.md. Both share_environment and sync_environment were removed
// outright per the locked build plan. These tests make sure they (or any
// renamed equivalent that hands key material to an agent) can never come back.

package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
)

// deniedMCPTools lists tool names that must never be registered again.
var deniedMCPTools = map[string]string{
	"share_environment": "returned the vault root key to agents with no approval gate (audit finding, Phase 0 item 0.1)",
	"sync_environment":  "agent-facing vault sync stub removed alongside share_environment (Phase 0 item 0.1)",
}

// keyExportPhrases catches a renamed tool that reintroduces key export to
// agents. Any MCP tool description advertising key export is a finding.
var keyExportPhrases = []string{
	"export the vault encryption key",
	"share the following key",
	"vault root key",
	"vault encryption key",
}

// guardFixture builds a minimal policy project in a temp dir with a
// hermetic HOME so vault.DefaultDir() can never touch the real keychain.
func guardFixture(t *testing.T) (*policy.File, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte("version: \"1\"\nprovider: passthrough\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return &policy.File{Version: "1", Provider: "passthrough"}, policyPath
}

// TestRemovedToolsStayRemoved enforces the static half of the invariant:
// the banned tools are gone and no tool advertises key export.
func TestRemovedToolsStayRemoved(t *testing.T) {
	f, policyPath := guardFixture(t)
	seen := map[string]bool{}
	for _, rt := range registeredTools(f, policyPath, "guard-session", nil) {
		name := rt.tool.Name
		if seen[name] {
			t.Errorf("duplicate MCP tool registered: %q", name)
		}
		seen[name] = true
		if reason, banned := deniedMCPTools[name]; banned {
			t.Errorf("banned MCP tool %q is registered again: %s", name, reason)
		}
		desc := strings.ToLower(rt.tool.Description)
		for _, phrase := range keyExportPhrases {
			if strings.Contains(desc, phrase) {
				t.Errorf("tool %q description advertises key export (%q): %q", name, phrase, rt.tool.Description)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no MCP tools registered; registry enumeration is broken")
	}
	t.Logf("guard enumerated %d registered tools", len(seen))
}

// invokeGuarded calls a tool handler with an empty request. Every handler
// must validate arguments before doing anything, so an empty request can only
// produce a validation error — never execution, mutation, or a block on human
// approval. A panic is reported as a failure rather than crashing the suite.
func invokeGuarded(t *testing.T, name string, h server.ToolHandlerFunc) (result *mcplib.CallToolResult) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("tool %q panicked on empty request: %v", name, r)
		}
	}()
	var err error
	result, err = h(context.Background(), mcplib.CallToolRequest{})
	if err != nil {
		t.Errorf("tool %q returned a Go error instead of a tool result: %v", name, err)
	}
	return result
}

// resultContainsKeyMaterial reports whether any text content in the tool
// resultContainsKeyMaterial reports whether any text content in the tool
// result contains the given key material.
func resultContainsKeyMaterial(result *mcplib.CallToolResult, keyMaterial string) bool {
	if result == nil || keyMaterial == "" {
		return false
	}
	for _, c := range result.Content {
		tc, ok := c.(mcplib.TextContent)
		if !ok {
			continue
		}
		if strings.Contains(tc.Text, keyMaterial) {
			return true
		}
	}
	return false
}

// TestKeyMaterialScannerCatchesLeak is the negative control for the guard:
// it proves the scanner above would actually flag a leaking handler, so the
// live probe cannot pass vacuously because of a broken check.
func TestKeyMaterialScannerCatchesLeak(t *testing.T) {
	fakeKey := "dGVzdC1mYWtlLXJvb3Qta2V5LWZvci1uZWdhdGl2ZS1jbw==" // 44-char base64, the ExportRootKey shape
	leaking := mcplib.NewToolResultText("Share the following key over a secure channel:\nKey: " + fakeKey + "\n")
	if !resultContainsKeyMaterial(leaking, fakeKey) {
		t.Fatal("scanner failed to flag a result containing key material; the guard is broken")
	}
	clean := mcplib.NewToolResultText("Available commands:\n  • greet: [echo hello]\n")
	if resultContainsKeyMaterial(clean, fakeKey) {
		t.Fatal("scanner flagged a clean result; the guard would false-positive")
	}
	if resultContainsKeyMaterial(nil, fakeKey) {
		t.Fatal("scanner flagged a nil result")
	}
}

// TestNoToolResultContainsKeyMaterial is the dynamic half of the invariant:
// with a real vault open, no tool's result may contain the vault root key.
// Handlers that can reach envset.Open run their full logic here (metadata
// tools take no required args); the rest fail fast on argument validation,
// which also verifies the error paths don't leak key material.
func TestNoToolResultContainsKeyMaterial(t *testing.T) {
	f, policyPath := guardFixture(t)
	root := projectRoot(policyPath)

	m, err := envset.Open(root)
	if err != nil {
		t.Skipf("no native credential store available (%v); live key-material probe skipped — static guard in TestRemovedToolsStayRemoved still enforced", err)
	}
	exporter, ok := m.Store.(interface{ ExportRootKey() string })
	if !ok {
		t.Skip("store does not expose ExportRootKey; live key-material probe skipped")
	}
	rootKey := exporter.ExportRootKey()
	if rootKey == "" {
		t.Fatal("ExportRootKey returned empty; cannot probe for key material")
	}

	// The scanner itself is validated by TestKeyMaterialScannerCatchesLeak,
	// so a pass here means no tool leaked — not that the check is broken.
	for _, rt := range registeredTools(f, policyPath, "guard-session", nil) {
		result := invokeGuarded(t, rt.tool.Name, rt.handler)
		if resultContainsKeyMaterial(result, rootKey) {
			t.Errorf("tool %q returned vault key material in its result text", rt.tool.Name)
		}
	}
}
