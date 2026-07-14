package localapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	data := []byte(`version: "1"
provider: passthrough
audit_log: "off"
commands:
  - id: greet
    argv: [echo, hello]
`)
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
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
