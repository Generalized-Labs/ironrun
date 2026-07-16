package mcp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/pending"
)

const proposalPolicy = `version: "1"
provider: passthrough
allow_proposals: true
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`

const noProposalPolicy = `version: "1"
provider: passthrough
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`

func writePolicyInDir(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ironrun.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (p *mcpProc) callTool(t *testing.T, id int, name string, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]interface{}{"name": name, "arguments": args},
	})
	return p.readResponse(t, 10*time.Second)
}

// TestMCP_ProposeThenSealClosed is the headline security test: an agent can
// propose a command but can NEVER self-approve or run it. The waiting call
// terminates safely if the human rejects/removes the proposal.
func TestMCP_ProposeThenSealClosed(t *testing.T) {
	policyFile := writePolicyInDir(t, proposalPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	// 1. Propose a new command — it stages, runs nothing.
	resp := p.callTool(t, 3, "propose_command", map[string]interface{}{
		"id":     "list-files",
		"argv":   []string{"ls", "-la"},
		"reason": "inspect the build output",
	})
	text, isErr := extractToolText(t, resp)
	if isErr {
		t.Fatalf("propose_command errored: %s", text)
	}
	if !strings.Contains(text, "approve") {
		t.Errorf("expected approval guidance, got: %s", text)
	}

	// 2. The proposal is staged in .ironrun/pending.yml, status pending.
	pendingFile := filepath.Join(filepath.Dir(policyFile), ".ironrun", "pending.yml")
	data, err := os.ReadFile(pendingFile)
	if err != nil {
		t.Fatalf("pending file not written: %v", err)
	}
	if !strings.Contains(string(data), "list-files") || !strings.Contains(string(data), "status: pending") {
		t.Errorf("pending file missing the proposal: %s", data)
	}

	// 3. CRITICAL: run_sealed waits and does not execute the unapproved id.
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]interface{}{"name": "run_sealed", "arguments": map[string]interface{}{"command_id": "list-files"}},
	})
	time.Sleep(150 * time.Millisecond)
	store, err := pending.Load(pendingFile)
	if err != nil {
		t.Fatal(err)
	}
	store.Remove("list-files")
	if err := pending.Save(pendingFile, store); err != nil {
		t.Fatal(err)
	}
	resp2 := p.readResponse(t, 10*time.Second)
	text2, _ := extractToolText(t, resp2)
	if strings.Contains(text2, "exit_code") {
		t.Errorf("AGENT SELF-APPROVAL HOLE: run_sealed executed an unapproved command:\n%s", text2)
	}
	if !strings.Contains(text2, "rejected or removed") {
		t.Errorf("expected a safe rejected response, got: %s", text2)
	}
}

func TestMCP_Propose_DisabledByDefault(t *testing.T) {
	policyFile := writePolicyInDir(t, noProposalPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	resp := p.callTool(t, 3, "propose_command", map[string]interface{}{
		"id":     "x",
		"argv":   []string{"ls"},
		"reason": "because",
	})
	text, _ := extractToolText(t, resp)
	if !strings.Contains(text, "disabled") {
		t.Errorf("expected proposals-disabled message, got: %s", text)
	}
	pendingFile := filepath.Join(filepath.Dir(policyFile), ".ironrun", "pending.yml")
	if _, err := os.Stat(pendingFile); !os.IsNotExist(err) {
		t.Errorf("pending file must not be written when proposals are disabled")
	}
}

func TestMCP_Propose_ShellRejected(t *testing.T) {
	policyFile := writePolicyInDir(t, proposalPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	resp := p.callTool(t, 3, "propose_command", map[string]interface{}{
		"id":     "shellcmd",
		"argv":   []string{"bash", "-c", "echo hi"},
		"reason": "need a shell",
	})
	text, _ := extractToolText(t, resp)
	if !strings.Contains(text, "shell") {
		t.Errorf("expected a shell-rejection message, got: %s", text)
	}
}

func TestMCP_ProposeToolListed(t *testing.T) {
	policyFile := writePolicyInDir(t, proposalPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	p.send(t, map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	resp := p.readResponse(t, 5*time.Second)
	result := resp["result"].(map[string]interface{})
	tools := result["tools"].([]interface{})
	for _, tool := range tools {
		if tm, ok := tool.(map[string]interface{}); ok && tm["name"] == "propose_command" {
			return
		}
	}
	t.Error("propose_command not advertised in tools/list")
}
