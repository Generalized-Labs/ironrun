package localapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/policy"
)

const defaultTestPolicy = `version: "1"
provider: passthrough
audit_log: "off"
commands:
  - id: greet
    argv: [echo, hello]
`

const leaseTestPolicy = `version: "1"
provider: passthrough
audit_log: "off"
require_agent_leases: true
commands:
  - id: greet
    argv: [echo, hello]
`

func testServer(t *testing.T) *Server {
	t.Helper()
	return testServerWithPolicy(t, defaultTestPolicy)
}

func testServerWithPolicy(t *testing.T, policyYAML string) *Server {
	t.Helper()
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(f, policyPath, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestStatusAndRunReturnValueBlindJSON(t *testing.T) {
	server := testServer(t)
	status := httptest.NewRecorder()
	server.Handler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"secret_values_exposed":false`) {
		t.Fatalf("status = %d %s", status.Code, status.Body.String())
	}

	body, _ := json.Marshal(runRequest{CommandID: "greet"})
	run := httptest.NewRecorder()
	server.Handler().ServeHTTP(run, httptest.NewRequest(http.MethodPost, "/v1/run", bytes.NewReader(body)))
	if run.Code != http.StatusOK || !strings.Contains(run.Body.String(), `"stdout":"hello\n"`) {
		t.Fatalf("run = %d %s", run.Code, run.Body.String())
	}
	if run.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("local API response is cacheable")
	}
}

func TestRunRejectsUnknownFieldsAndCommands(t *testing.T) {
	server := testServer(t)
	for _, body := range []string{
		`{"command_id":"greet","secret":"must-not-be-accepted"}`,
		`{"command_id":"not-in-policy"}`,
	} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(body)))
		if response.Code < 400 {
			t.Fatalf("unsafe request accepted: %s -> %d %s", body, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "must-not-be-accepted") {
			t.Fatal("API reflected a rejected secret field")
		}
	}
}

// approveTestLease creates and approves a lease for the given session,
// environment, and command, returning the lease. It mirrors what
// `ironrun access approve` does for a pending lease request.
func approveTestLease(t *testing.T, server *Server, sessionID, environment, command string) access.Lease {
	t.Helper()
	request, err := server.access.CreateLeaseRequest(sessionID, environment, []string{command}, time.Minute, "test")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := server.access.ApproveLease(request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func postRun(t *testing.T, server *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(body)))
	return response
}

func TestRunEnforcesAgentLeases(t *testing.T) {
	server := testServerWithPolicy(t, leaseTestPolicy)
	payload := `{"command_id":"greet"}`

	// No lease: the local API must fail closed exactly like the MCP path.
	denied := postRun(t, server, payload)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("run without lease = %d %s, want 403", denied.Code, denied.Body.String())
	}

	// With a human-approved lease for this session, environment, and command,
	// the run proceeds.
	approveTestLease(t, server, server.sessionID, "default", "greet")
	allowed := postRun(t, server, payload)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"stdout":"hello\n"`) {
		t.Fatalf("run with lease = %d %s, want 200 with command output", allowed.Code, allowed.Body.String())
	}
}

// TestRunDenialCreatesApprovableLeaseRequest is the regression test for the
// /v1/run dead end under require_agent_leases: the API session can hold no
// lease through any pre-existing flow (the MCP request_lease tool is bound to
// MCP sessions), so a bare 403 would make the endpoint permanently unusable.
// The denial must instead surface a real lease request the operator can
// approve, after which the run proceeds.
func TestRunDenialCreatesApprovableLeaseRequest(t *testing.T) {
	server := testServerWithPolicy(t, leaseTestPolicy)
	payload := `{"command_id":"greet"}`

	denied := postRun(t, server, payload)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("run without lease = %d, want 403", denied.Code)
	}
	if !strings.Contains(denied.Body.String(), "lease request") {
		t.Fatalf("403 body must point at the created lease request, got: %s", denied.Body.String())
	}

	// A repeat denial must reuse the pending request, not stack new ones.
	again := postRun(t, server, payload)
	if again.Code != http.StatusForbidden {
		t.Fatalf("second run without lease = %d, want 403", again.Code)
	}
	requests, err := server.access.Requests()
	if err != nil {
		t.Fatal(err)
	}
	var pending []access.Request
	for _, req := range requests {
		if req.Kind == access.RequestLease && req.Status == access.StatusPending &&
			req.SessionID == server.sessionID && req.Environment == "default" {
			pending = append(pending, req)
		}
	}
	if len(pending) != 1 {
		t.Fatalf("want exactly 1 pending lease request for the API session, got %d", len(pending))
	}
	if len(pending[0].Commands) != 1 || pending[0].Commands[0] != "greet" {
		t.Fatalf("lease request must scope to the requested command, got %v", pending[0].Commands)
	}

	// Approving that request (the operator's path) unblocks the endpoint.
	if _, err := server.access.ApproveLease(pending[0].ID, time.Minute); err != nil {
		t.Fatal(err)
	}
	allowed := postRun(t, server, payload)
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"stdout":"hello\n"`) {
		t.Fatalf("run after approving the lease request = %d %s, want 200 with output", allowed.Code, allowed.Body.String())
	}
}

func TestRunEnforcesAgentLeasesCommandScoped(t *testing.T) {
	server := testServerWithPolicy(t, leaseTestPolicy)
	// Lease granted for another session must not authorize this server's run.
	approveTestLease(t, server, "some-other-session", "default", "greet")
	denied := postRun(t, server, `{"command_id":"greet"}`)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("run with another session's lease = %d, want 403", denied.Code)
	}
}

func TestRevokeLeaseEnforcesSessionOwnership(t *testing.T) {
	server := testServer(t)

	// A lease owned by a different session cannot be revoked through the
	// local API: the ownership check must fail closed.
	foreign := approveTestLease(t, server, "some-other-session", "default", "greet")
	foreignRevoke := httptest.NewRecorder()
	server.Handler().ServeHTTP(foreignRevoke, httptest.NewRequest(http.MethodPost, "/v1/access/leases/"+foreign.ID+"/revoke", nil))
	if foreignRevoke.Code != http.StatusForbidden {
		t.Fatalf("revoke of foreign lease = %d %s, want 403", foreignRevoke.Code, foreignRevoke.Body.String())
	}
	leases, err := server.access.Leases("")
	if err != nil {
		t.Fatal(err)
	}
	for _, lease := range leases {
		if lease.ID == foreign.ID && lease.RevokedAt != nil {
			t.Fatal("foreign lease was revoked despite the ownership check")
		}
	}

	// The local API session can still revoke its own lease.
	own := approveTestLease(t, server, server.sessionID, "default", "greet")
	ownRevoke := httptest.NewRecorder()
	server.Handler().ServeHTTP(ownRevoke, httptest.NewRequest(http.MethodPost, "/v1/access/leases/"+own.ID+"/revoke", nil))
	if ownRevoke.Code != http.StatusOK {
		t.Fatalf("revoke of own lease = %d %s, want 200", ownRevoke.Code, ownRevoke.Body.String())
	}

	// Unknown lease IDs still 404.
	missing := httptest.NewRecorder()
	server.Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/v1/access/leases/lease-does-not-exist/revoke", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("revoke of unknown lease = %d, want 404", missing.Code)
	}
}

func TestSocketIsOwnerOnly(t *testing.T) {
	// Deliberately permissive process umask: the socket must still end up
	// 0600 because listenSecureSocket narrows the umask around bind itself.
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	socketPath := filepath.Join(t.TempDir(), "ironrun.sock")
	listener, err := listenSecureSocket(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("socket permission = %04o, want 0600", perm)
	}
}

// Tightening ironrun.yml must take effect on the next /v1/run without
// restarting `ironrun api`.
func TestRunReloadsPolicyPerRequest(t *testing.T) {
	server := testServer(t)
	if response := postRun(t, server, `{"command_id":"greet"}`); response.Code != http.StatusOK {
		t.Fatalf("baseline run = %d %s", response.Code, response.Body)
	}
	if err := os.WriteFile(server.policyPath, []byte(leaseTestPolicy), 0600); err != nil {
		t.Fatal(err)
	}
	if response := postRun(t, server, `{"command_id":"greet"}`); response.Code != http.StatusForbidden {
		t.Fatalf("run after enabling require_agent_leases = %d, want 403", response.Code)
	}
}
