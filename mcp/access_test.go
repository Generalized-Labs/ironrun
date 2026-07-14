package mcp_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/access"
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

var requestIDPattern = regexp.MustCompile(`req_[a-f0-9]{24}`)
var leaseIDPattern = regexp.MustCompile(`lease_[a-f0-9]{24}`)

func TestMCPLeaseRequiredApproveRunAndRevoke(t *testing.T) {
	policyFile := writePolicyInDir(t, leasePolicy)
	p := startMCP(t, policyFile)
	p.initialize(t)

	blocked := p.callTool(t, 3, "run_sealed", map[string]interface{}{"command_id": "greet"})
	blockedText, blockedErr := extractToolText(t, blocked)
	if !blockedErr || !strings.Contains(blockedText, "agent lease required") {
		t.Fatalf("unleased command was not blocked: isError=%v text=%s", blockedErr, blockedText)
	}

	requested := p.callTool(t, 4, "request_lease", map[string]interface{}{
		"command_ids": []string{"greet"},
		"ttl":         "30m",
		"reason":      "run the requested test",
	})
	requestText, requestErr := extractToolText(t, requested)
	if requestErr {
		t.Fatalf("request_lease failed: %s", requestText)
	}
	requestID := requestIDPattern.FindString(requestText)
	if requestID == "" {
		t.Fatalf("request response has no request id: %s", requestText)
	}

	manager, err := access.Open(filepath.Dir(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := manager.ApproveLease(requestID, 0)
	if err != nil {
		t.Fatal(err)
	}

	run := p.callTool(t, 5, "run_sealed", map[string]interface{}{"command_id": "greet"})
	runText, runErr := extractToolText(t, run)
	if runErr || !strings.Contains(runText, "exit_code: 0") || !strings.Contains(runText, "hello") {
		t.Fatalf("approved run failed: isError=%v text=%s", runErr, runText)
	}

	status := p.callTool(t, 6, "lease_status", map[string]interface{}{})
	statusText, statusErr := extractToolText(t, status)
	if statusErr || !strings.Contains(statusText, lease.ID) || !strings.Contains(statusText, "active") {
		t.Fatalf("lease_status = isError=%v text=%s", statusErr, statusText)
	}
	if leaseIDPattern.FindString(statusText) != lease.ID {
		t.Fatalf("lease id missing from status: %s", statusText)
	}

	revoked := p.callTool(t, 7, "revoke_own_lease", map[string]interface{}{"lease_id": lease.ID})
	revokedText, revokedErr := extractToolText(t, revoked)
	if revokedErr || !strings.Contains(revokedText, "revoked") {
		t.Fatalf("revoke failed: isError=%v text=%s", revokedErr, revokedText)
	}
	after := p.callTool(t, 8, "run_sealed", map[string]interface{}{"command_id": "greet"})
	afterText, afterErr := extractToolText(t, after)
	if !afterErr || !strings.Contains(afterText, "agent lease required") {
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
	resp := second.callTool(t, 4, "run_sealed", map[string]interface{}{"command_id": "greet"})
	text, isErr := extractToolText(t, resp)
	if !isErr || !strings.Contains(text, "agent lease required") {
		t.Fatalf("lease transferred to a new server session: isError=%v text=%s", isErr, text)
	}
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
