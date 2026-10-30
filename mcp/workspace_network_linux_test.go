//go:build linux

package mcp_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/access"
)

// This exercises the actual CLI, encrypted v2 vault, MCP stdio process,
// authorization persistence, runner, and redactor. Only the platform root-key
// provider is a synthetic secret-tool adapter; it does not validate Secret
// Service, a real agent host, or human usability.
func TestMCPTrustedWorkspaceLoopbackAndRevocation(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	binDir := filepath.Join(root, "bin")
	nativeDir := filepath.Join(root, "synthetic-native-store")
	for _, dir := range []string{home, binDir, nativeDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	probe := filepath.Join(binDir, "secret-tool")
	build := exec.Command("go", "build", "-o", probe, "./testdata/workspaceprobe")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build local probe: %v\n%s", err, output)
	}
	t.Setenv("HOME", home)
	t.Setenv("IRONRUN_HOME", filepath.Join(home, "ironrun"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("IRONRUN_TEST_NATIVE_STORE_DIR", nativeDir)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	value := "synthetic-loopback-token-" + strings.Repeat("fixture", 4)
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Get("X-Ironrun-Fixture")
		_, _ = fmt.Fprintln(w, "LOOPBACK_RESPONSE "+value)
	}))
	defer server.Close()
	argv, err := json.Marshal([]string{probe, "http", server.URL})
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(root, "ironrun.yml")
	policy := fmt.Sprintf("version: \"2\"\ncommands:\n  - id: strict-loopback\n    argv: %s\n    secrets: [IRONRUN_E2E_TOKEN]\n    ttl: 5s\n", argv)
	if err := os.WriteFile(policyPath, []byte(policy), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(input string, args ...string) {
		t.Helper()
		cmd := exec.Command(mcpBin, args...)
		cmd.Dir = root
		cmd.Stdin = strings.NewReader(input)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture CLI %v: %v\n%s", args, err, output)
		}
	}
	cli("", "env", "init", "dev")
	cli(value+"\n", "env", "set", "dev", "IRONRUN_E2E_TOKEN", "--from-stdin", "--unsafe")
	cli("", "doctor")
	p := startMCP(t, policyPath)
	p.initialize(t)
	tools := p.callTool(t, 2, "workspace_status", map[string]interface{}{})
	status, statusErr := extractToolText(t, tools)
	if statusErr || !strings.Contains(status, "IRONRUN_E2E_TOKEN") || !strings.Contains(status, "not trusted") || strings.Contains(status, value) {
		t.Fatalf("unexpected initial workspace metadata: isError=%v text=%s", statusErr, status)
	}
	manager, err := access.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	call := func(id int) {
		p.send(t, map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]interface{}{
			"name": "run_sealed", "arguments": map[string]interface{}{"argv": []string{probe, "http", server.URL}},
		}})
	}
	call(3)
	request := waitForPendingRequest(t, manager, "", access.RequestWorkspace)
	select {
	case <-requests:
		t.Fatal("command reached loopback before human approval")
	case <-time.After(100 * time.Millisecond):
		// Keep the grant pending long enough to observe an eager execution;
		// checking only at the instant the request appears would be vacuous.
	}
	cli("", "trust", "grant", request.ID, "--ttl", "1m")
	grant, err := manager.AuthorizeWorkspace(request.SessionID, request.Environment)
	if err != nil {
		t.Fatal(err)
	}
	response := p.readResponse(t, 10*time.Second)
	text, isErr := extractToolText(t, response)
	if isErr || !strings.Contains(text, "exit_code: 0") || !strings.Contains(text, "DIAL_OK") || !strings.Contains(text, "LOOPBACK_RESPONSE [REDACTED]") || strings.Contains(text, value) {
		t.Fatalf("approved normal-network workspace did not execute and redact loopback: isError=%v text=%s", isErr, text)
	}
	select {
	case received := <-requests:
		if received != value {
			t.Fatal("child did not receive the configured synthetic credential")
		}
	default:
		t.Fatal("successful result lacked an actual loopback request")
	}

	// The workspace opt-out must not silently relax saved strict commands.
	strict := p.callTool(t, 4, "run_sealed", map[string]interface{}{"command_id": "strict-loopback"})
	strictText, strictErr := extractToolText(t, strict)
	if strictErr {
		if !strings.Contains(strictText, "network namespace creation was denied") {
			t.Fatalf("strict probe failed for an unrelated reason: %s", strictText)
		}
		t.Log("strict network isolation failed closed before execution; this host does not establish an attempted blocked dial")
	} else if strings.Contains(strictText, "exit_code: 0") || !strings.Contains(strictText, "PROBE_STARTED") || !strings.Contains(strictText, "DIAL_BLOCKED") {
		t.Fatalf("strict command lost its network restriction: %s", strictText)
	}
	select {
	case <-requests:
		t.Fatal("strict isolated command reached the loopback endpoint")
	default:
	}
	if strings.Contains(strictText, value) {
		t.Fatal("strict command exposed the configured synthetic credential")
	}

	cli("", "trust", "revoke", grant.ID)
	call(5)
	retry := waitForPendingRequest(t, manager, request.ID, access.RequestWorkspace)
	cli("", "access", "deny", retry.ID)
	denied := p.readResponse(t, 10*time.Second)
	deniedText, deniedErr := extractToolText(t, denied)
	if !deniedErr || !strings.Contains(deniedText, "denied") {
		t.Fatalf("revoked workspace ran without fresh approval: isError=%v text=%s", deniedErr, deniedText)
	}
	select {
	case <-requests:
		t.Fatal("revoked/denied workspace reached loopback")
	default:
	}
}
