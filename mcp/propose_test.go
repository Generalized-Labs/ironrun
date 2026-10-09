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

// The proposal boundary: agent text must be single-line, bindings must be
// env-var names, a pending id is immutable (approval binds to the id), and
// allow_proposals is re-read on every call.
func TestMCP_ProposeBoundary(t *testing.T) {
	policyFile := writePolicyInDir(t, proposalPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)
	propose := func(id int, args map[string]interface{}) (string, bool) {
		return extractToolText(t, p.callTool(t, id, "propose_command", args))
	}

	if text, isErr := propose(3, map[string]interface{}{"id": "a", "argv": []string{"ls"}, "reason": "x\n  - id: evil"}); !isErr {
		t.Fatalf("multi-line reason accepted: %s", text)
	}
	if text, isErr := propose(4, map[string]interface{}{"id": "a", "argv": []string{"ls"}, "reason": "x", "env": map[string]interface{}{"A: b\n- id: evil": "A"}}); !isErr {
		t.Fatalf("non env-var binding name accepted: %s", text)
	}
	if text, isErr := propose(5, map[string]interface{}{"id": "a", "argv": []string{"ls"}, "reason": "list"}); isErr {
		t.Fatalf("valid proposal rejected: %s", text)
	}
	if text, isErr := propose(6, map[string]interface{}{"id": "a", "argv": []string{"ls"}, "reason": "list"}); isErr {
		t.Fatalf("identical re-proposal should be idempotent: %s", text)
	}
	if text, isErr := propose(7, map[string]interface{}{"id": "a", "argv": []string{"rm", "-rf", "/"}, "reason": "list"}); !isErr {
		t.Fatalf("pending proposal content was swapped: %s", text)
	}
	store, err := pending.Load(filepath.Join(filepath.Dir(policyFile), ".ironrun", "pending.yml"))
	if err != nil || len(store.Proposals) != 1 || store.Proposals[0].Argv[0] != "ls" {
		t.Fatalf("pending store = %+v, %v", store, err)
	}

	if err := os.WriteFile(policyFile, []byte(noProposalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if text, isErr := propose(8, map[string]interface{}{"id": "b", "argv": []string{"ls"}, "reason": "list"}); !isErr {
		t.Fatalf("allow_proposals turned off but proposal accepted: %s", text)
	}
}
