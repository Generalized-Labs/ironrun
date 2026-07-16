package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/execution"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/runner"
)

func TestRunHandlerPinsAuthorizedEnvironmentForExecution(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	f := &policy.File{
		Version:            "1",
		Provider:           "passthrough",
		EnvironmentSet:     "active",
		RequireAgentLeases: true,
		Commands: []policy.Command{{
			ID: "greet", Argv: []string{"echo", "hello"},
		}},
	}
	if err := os.WriteFile(policyPath, []byte(`version: "1"
provider: passthrough
environment_set: active
require_agent_leases: true
commands:
  - id: greet
    argv: [echo, hello]
    ttl: 5s
`), 0600); err != nil {
		t.Fatal(err)
	}

	manager, err := access.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := manager.CreateLeaseRequest("session-a", "reviewed-env", []string{"greet"}, time.Minute, "regression test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveLease(request.ID, time.Minute); err != nil {
		t.Fatal(err)
	}

	originalExecute := executeCommand
	originalEnvironment := resolveExecutionEnvironment
	t.Cleanup(func() { executeCommand = originalExecute; resolveExecutionEnvironment = originalEnvironment })
	resolveExecutionEnvironment = func(*policy.File, string) (string, error) { return "reviewed-env", nil }
	var gotEnvironment string
	executeCommand = func(_ context.Context, _ *policy.File, _, _, _ string, opts execution.Options) (*runner.Result, error) {
		gotEnvironment = opts.Environment
		return &runner.Result{}, nil
	}

	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Arguments: map[string]any{"command_id": "greet"},
	}}
	result, err := makeRunHandler(f, (*audit.Logger)(nil), "session-a", policyPath)(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("run handler returned an error: %#v", result.Content)
	}
	if gotEnvironment != "reviewed-env" {
		t.Fatalf("execution environment = %q, want authorized environment %q", gotEnvironment, "reviewed-env")
	}
}

func TestRunHandlerReloadsNewlyApprovedCommand(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte(`version: "1"
provider: passthrough
commands:
  - id: newly-approved
    argv: [echo, approved]
    ttl: 5s
`), 0600); err != nil {
		t.Fatal(err)
	}

	startupSnapshot := &policy.File{Version: "1", Provider: "passthrough"}
	originalExecute := executeCommand
	t.Cleanup(func() { executeCommand = originalExecute })
	var gotCommand string
	executeCommand = func(_ context.Context, _ *policy.File, _, _, commandID string, _ execution.Options) (*runner.Result, error) {
		gotCommand = commandID
		return &runner.Result{}, nil
	}
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Arguments: map[string]any{"command_id": "newly-approved"},
	}}
	result, err := makeRunHandler(startupSnapshot, nil, "session-a", policyPath)(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("newly approved command was not reloaded: %#v", result.Content)
	}
	if gotCommand != "newly-approved" {
		t.Fatalf("executed command = %q, want newly-approved", gotCommand)
	}
}

func TestRunHandlerTrustedWorkspacePinsEnvironmentAndArgv(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte(`version: "1"
provider: passthrough
commands:
  - id: strict
    argv: [echo, strict]
`), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := access.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	request, err := manager.CreateWorkspaceRequest("session-a", "dev", []string{"go", "test", "./..."}, time.Hour, "trusted test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveWorkspace(request.ID, time.Hour); err != nil {
		t.Fatal(err)
	}

	originalExecute := executeWorkspace
	originalEnvironment := resolveExecutionEnvironment
	t.Cleanup(func() { executeWorkspace = originalExecute; resolveExecutionEnvironment = originalEnvironment })
	resolveExecutionEnvironment = func(*policy.File, string) (string, error) { return "dev", nil }
	var gotRoot, gotEnvironment string
	var gotArgv []string
	executeWorkspace = func(_ context.Context, root, environment string, argv []string, _ execution.Options) (*runner.Result, error) {
		gotRoot, gotEnvironment, gotArgv = root, environment, append([]string(nil), argv...)
		return &runner.Result{}, nil
	}
	requestCall := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"argv": []string{"go", "test", "./..."}}}}
	result, err := makeRunHandler(&policy.File{Version: "1", Provider: "passthrough"}, nil, "session-a", policyPath)(context.Background(), requestCall)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("trusted workspace handler returned error: %#v", result.Content)
	}
	if gotRoot != root || gotEnvironment != "dev" || len(gotArgv) != 3 || gotArgv[0] != "go" {
		t.Fatalf("workspace execution scope = root=%q env=%q argv=%q", gotRoot, gotEnvironment, gotArgv)
	}
}

func TestRunHandlerTrustedWorkspaceWaitsAndResumesAfterGrant(t *testing.T) {
	root := t.TempDir()
	policyPath := filepath.Join(root, "ironrun.yml")
	if err := os.WriteFile(policyPath, []byte(`version: "1"
provider: passthrough
commands:
  - id: strict
    argv: [echo, strict]
`), 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := access.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	originalExecute := executeWorkspace
	originalEnvironment := resolveExecutionEnvironment
	t.Cleanup(func() { executeWorkspace = originalExecute; resolveExecutionEnvironment = originalEnvironment })
	resolveExecutionEnvironment = func(*policy.File, string) (string, error) { return "dev", nil }
	executeWorkspace = func(_ context.Context, _ string, environment string, argv []string, _ execution.Options) (*runner.Result, error) {
		if environment != "dev" || len(argv) != 2 || argv[0] != "go" {
			t.Errorf("unexpected trusted run scope env=%q argv=%q", environment, argv)
		}
		return &runner.Result{}, nil
	}
	resultCh := make(chan *mcplib.CallToolResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, runErr := makeRunHandler(&policy.File{Version: "1", Provider: "passthrough"}, nil, "session-a", policyPath)(context.Background(), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: map[string]any{"argv": []string{"go", "test"}}}})
		resultCh <- result
		errCh <- runErr
	}()
	var request access.Request
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		requests, listErr := manager.Requests()
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, candidate := range requests {
			if candidate.Kind == access.RequestWorkspace && candidate.Status == access.StatusPending {
				request = candidate
				break
			}
		}
		if request.ID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if request.ID == "" {
		t.Fatal("trusted workspace request was not created")
	}
	if _, err := manager.ApproveWorkspace(request.ID, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
		if result := <-resultCh; result.IsError {
			t.Fatalf("resumed workspace run errored: %#v", result.Content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trusted workspace run did not resume after approval")
	}
}
