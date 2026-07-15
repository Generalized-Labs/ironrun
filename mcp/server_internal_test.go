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
		RequireAgentLeases: true,
		Commands: []policy.Command{{
			ID: "greet", Argv: []string{"echo", "hello"},
		}},
	}
	if err := os.WriteFile(policyPath, []byte(`version: "1"
provider: passthrough
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
	request, err := manager.CreateLeaseRequest("session-a", "default", []string{"greet"}, time.Minute, "regression test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ApproveLease(request.ID, time.Minute); err != nil {
		t.Fatal(err)
	}

	originalExecute := executeCommand
	t.Cleanup(func() { executeCommand = originalExecute })
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
	if gotEnvironment != "default" {
		t.Fatalf("execution environment = %q, want authorized environment %q", gotEnvironment, "default")
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
