package mcp_test

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/access"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

const leasePolicy = `version: "1"
provider: passthrough
require_agent_leases: true
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`

const secretRequestPolicy = `version: "1"
provider: passthrough
secrets:
  openai:
    env: OPENAI_API_KEY
    store: envfile
    allow: [greet]
commands:
  - id: greet
    argv: [echo, hello]
    secrets: [openai]
    ttl: 5s
`

const autoSecretPolicy = `version: "1"
provider: passthrough
secrets:
  openrouter:
    env: OPENROUTER_API_KEY
    store: envfile
    allow: [show-key]
commands:
  - id: show-key
    argv: [printenv, OPENROUTER_API_KEY]
    secrets: [openrouter]
    ttl: 5s
`

var requestIDPattern = regexp.MustCompile(`req_[a-f0-9]{24}`)
var leaseIDPattern = regexp.MustCompile(`lease_[a-f0-9]{24}`)

func TestMCPLeaseRequiredApproveRunAndRevoke(t *testing.T) {
	policyFile := writePolicyInDir(t, leasePolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	manager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{"name": "run_sealed", "arguments": map[string]interface{}{"command_id": "greet"}},
	})
	request := waitForPendingRequest(t, manager, "", access.RequestLease)
	lease, err := manager.ApproveLease(request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	run := p.readResponse(t, 10*time.Second)
	runText, runErr := extractToolText(t, run)
	if runErr || !strings.Contains(runText, "exit_code: 0") || !strings.Contains(runText, "hello") {
		t.Fatalf("approved run failed: isError=%v text=%s", runErr, runText)
	}

	status := p.callTool(t, 4, "lease_status", map[string]interface{}{})
	statusText, statusErr := extractToolText(t, status)
	if statusErr || !strings.Contains(statusText, lease.ID) || !strings.Contains(statusText, "active") {
		t.Fatalf("lease_status = isError=%v text=%s", statusErr, statusText)
	}
	if leaseIDPattern.FindString(statusText) != lease.ID {
		t.Fatalf("lease id missing from status: %s", statusText)
	}

	revoked := p.callTool(t, 5, "revoke_own_lease", map[string]interface{}{"lease_id": lease.ID})
	revokedText, revokedErr := extractToolText(t, revoked)
	if revokedErr || !strings.Contains(revokedText, "revoked") {
		t.Fatalf("revoke failed: isError=%v text=%s", revokedErr, revokedText)
	}
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]interface{}{"name": "run_sealed", "arguments": map[string]interface{}{"command_id": "greet"}},
	})
	request = waitForPendingRequest(t, manager, request.ID, access.RequestLease)
	if err := manager.Deny(request.ID); err != nil {
		t.Fatal(err)
	}
	after := p.readResponse(t, 10*time.Second)
	afterText, afterErr := extractToolText(t, after)
	if !afterErr || !strings.Contains(afterText, "denied") {
		t.Fatalf("revoked lease still authorized: isError=%v text=%s", afterErr, afterText)
	}
}

func TestMCPLeaseDoesNotTransferAcrossServerSessions(t *testing.T) {
	policyFile := writePolicyInDir(t, leasePolicy)
	first := startMCP(t, policyFile)
	first.initialize(t)
	requested := first.callTool(t, 3, "request_lease", map[string]interface{}{
		"command_ids": []string{"greet"}, "ttl": "30m", "reason": "first session",
	})
	requestText, _ := extractToolText(t, requested)
	requestID := requestIDPattern.FindString(requestText)
	manager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveLease(requestID, 0); err != nil {
		t.Fatal(err)
	}

	second := startMCP(t, policyFile)
	second.initialize(t)
	secondManager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	second.send(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call",
		"params": map[string]interface{}{"name": "run_sealed", "arguments": map[string]interface{}{"command_id": "greet"}},
	})
	secondRequest := waitForPendingRequest(t, secondManager, requestID, access.RequestLease)
	if err := secondManager.Deny(secondRequest.ID); err != nil {
		t.Fatal(err)
	}
	resp := second.readResponse(t, 10*time.Second)
	text, isErr := extractToolText(t, resp)
	if !isErr || !strings.Contains(text, "denied") {
		t.Fatalf("lease transferred to a new server session: isError=%v text=%s", isErr, text)
	}
}

func waitForPendingRequest(t *testing.T, manager *access.Manager, exclude string, kind access.RequestKind) access.Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		requests, err := manager.Requests()
		if err == nil {
			for _, request := range requests {
				if request.ID != exclude && request.Kind == kind && request.Status == access.StatusPending {
					return request
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for automatic pending request")
	return access.Request{}
}

func TestMCPSecretRequestStoresMetadataOnly(t *testing.T) {
	policyFile := writePolicyInDir(t, secretRequestPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	marker := "sk-must-never-enter-access-state"
	resp := p.callTool(t, 3, "request_secret", map[string]interface{}{
		"secret_alias": "openai",
		"reason":       "configure the declared key",
		"value":        marker, // undeclared input must never be persisted or reflected
	})
	text, isErr := extractToolText(t, resp)
	if isErr || !strings.Contains(text, "No value was accepted or exposed") {
		t.Fatalf("request_secret failed: isError=%v text=%s", isErr, text)
	}
	if strings.Contains(text, marker) {
		t.Fatal("MCP response reflected an undeclared plaintext value")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(policyFile), ".ironrun", "access.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), marker) {
		t.Fatal("access state persisted an undeclared plaintext value")
	}
}

func TestMCPWorkspaceAccessRequestIsValueBlindAndDeduplicated(t *testing.T) {
	policyFile := writePolicyInDir(t, leasePolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)
	marker := "sk-must-never-enter-workspace-request"
	resp := p.callTool(t, 3, "request_workspace_access", map[string]interface{}{
		"reason": "run the local development checks",
		"argv":   []string{"go", "test", "./..."},
		"value":  marker,
	})
	text, isErr := extractToolText(t, resp)
	if isErr || !strings.Contains(text, "pending") {
		t.Fatalf("workspace request failed: isError=%v text=%s", isErr, text)
	}
	manager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	request := waitForPendingRequest(t, manager, "", access.RequestWorkspace)
	if len(request.FirstArgv) == 0 || request.FirstArgv[0] != "go" {
		t.Fatalf("workspace request lost argv metadata: %#v", request)
	}
	data, err := os.ReadFile(manager.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), marker) {
		t.Fatal("workspace request persisted a plaintext value")
	}
	grant, err := manager.ApproveWorkspace(request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthorizeWorkspace(request.SessionID, request.Environment); err != nil {
		t.Fatal(err)
	}
	if err := manager.RevokeWorkspace(grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.AuthorizeWorkspace(request.SessionID, request.Environment); !errors.Is(err, access.ErrUnauthorized) {
		t.Fatalf("revoked workspace grant still authorizes: %v", err)
	}
}

func TestMCPRunCreatesMissingSecretRequestAndResumesRedacted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	policyFile := writePolicyInDir(t, autoSecretPolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)
	manager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	p.send(t, map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{"name": "run_sealed", "arguments": map[string]interface{}{"command_id": "show-key"}},
	})
	request := waitForPendingRequest(t, manager, "", access.RequestSecret)
	if request.SecretAlias != "openrouter" || len(request.Commands) != 1 || request.Commands[0] != "show-key" {
		t.Fatalf("automatic request lost run context: %#v", request)
	}
	value := "sk-" + strings.Repeat("dummy", 8)
	store, err := secretstore.Open(policyFile, "envfile")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("openrouter", value); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FulfillSecret(request.ID); err != nil {
		t.Fatal(err)
	}
	response := p.readResponse(t, 10*time.Second)
	text, isErr := extractToolText(t, response)
	if isErr || !strings.Contains(text, "exit_code: 0") || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("waiting sealed run did not resume with redaction: isError=%v text=%s", isErr, text)
	}
	if strings.Contains(text, value) {
		t.Fatal("sealed output exposed the configured value")
	}
}
