// Package mcp exposes ironrun as an MCP stdio server.
// AI agents (Claude Code, Cursor, any MCP host) can call run_sealed to execute
// policy-authorized commands without receiving raw secret values.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/buildinfo"
	"github.com/generalized-labs/ironrun/internal/capsule"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/execution"
	"github.com/generalized-labs/ironrun/internal/pending"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/runner"
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

var executeCommand = execution.Run
var executeWorkspace = execution.RunWorkspace
var resolveExecutionEnvironment = executionEnvironment

// Serve starts the MCP stdio server using the given policy. policyPath locates
// the pending-proposal store (.ironrun/pending.yml next to it).
// It blocks until the client disconnects or the process exits.
func Serve(f *policy.File, policyPath string) error {
	// One audit logger and session id for the life of this server process, so
	// every run_sealed call from the same agent session shares a session id.
	auditLog, err := audit.Open(audit.ResolvePath(f.AuditLog))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ironrun] warning: audit log disabled: %v\n", err)
	}
	defer auditLog.Close()
	sessionID := audit.NewSessionID()

	s := server.NewMCPServer(
		"ironrun",
		buildinfo.String(),
		server.WithToolCapabilities(true),
	)

	// Tool: list_commands — let the agent discover available command IDs.
	listTool := mcplib.NewTool("list_commands",
		mcplib.WithDescription("List all command IDs available in the current policy. "+
			"Call this first to know what commands you can run via run_sealed."),
	)
	s.AddTool(listTool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		current, err := currentPolicy(f, policyPath)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("policy reload failed: %v", err)), nil
		}
		out := "Available commands:\n"
		for _, cmd := range current.Commands {
			out += fmt.Sprintf("  • %s: %v\n", cmd.ID, cmd.Argv)
		}
		return mcplib.NewToolResultText(out), nil
	})

	// Tool: run_sealed supports both legacy strict command IDs and a human-
	// approved trusted workspace session. Exactly one argument form is allowed.
	runTool := mcplib.NewTool("run_sealed",
		mcplib.WithDescription(
			"Execute either a policy-authorized command by command_id or argv in a human-trusted workspace session. "+
				"Secrets are injected below agent visibility and redacted from all output. "+
				"The agent never sees raw secret values.",
		),
		mcplib.WithString("command_id", mcplib.Description("Legacy policy command ID (strict mode)")),
		mcplib.WithArray("argv", mcplib.WithStringItems(), mcplib.Description("Exact argv for the current human-trusted workspace session")),
	)
	s.AddTool(runTool, makeRunHandler(f, auditLog, sessionID, policyPath))

	workspaceStatusTool := mcplib.NewTool("workspace_status",
		mcplib.WithDescription("Return value-blind current project, environment, configured entry names, and this agent session's trusted-access status."),
	)
	s.AddTool(workspaceStatusTool, makeWorkspaceStatusHandler(policyPath, sessionID))

	requestWorkspaceTool := mcplib.NewTool("request_workspace_access",
		mcplib.WithDescription("Ask the human to trust this MCP session for the current project's selected environment. Access is temporary, revocable, and never includes secret values in MCP."),
		mcplib.WithString("reason", mcplib.Required(), mcplib.Description("Brief task reason shown to the human")),
		mcplib.WithArray("argv", mcplib.WithStringItems(), mcplib.Description("Optional first command for human context; it is not executed by this request")),
	)
	s.AddTool(requestWorkspaceTool, makeRequestWorkspaceHandler(f, policyPath, sessionID))

	// Tool: validate_policy — sanity-check the loaded policy.
	validateTool := mcplib.NewTool("validate_policy",
		mcplib.WithDescription("Validate the current policy file and return a summary of defined commands."),
	)
	s.AddTool(validateTool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		current, err := currentPolicy(f, policyPath)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("policy reload failed: %v", err)), nil
		}
		out := fmt.Sprintf("Policy OK: %d command(s), provider=%s\n", len(current.Commands), current.Provider)
		return mcplib.NewToolResultText(out), nil
	})

	// Tool: propose_command — stage a NEW command for human approval. It does
	// NOT run anything; a human must `ironrun approve <id>` before it can run.
	proposeTool := mcplib.NewTool("propose_command",
		mcplib.WithDescription(
			"Stage a NEW command for the user to approve when it is not in the policy. "+
				"This does NOT run anything — a human must approve it with `ironrun approve <id>` "+
				"in their terminal before run_sealed can execute it. Use this instead of giving up "+
				"or running the command in a raw shell.",
		),
		mcplib.WithString("id", mcplib.Required(),
			mcplib.Description("Short kebab-case id for the command, e.g. db-shell")),
		mcplib.WithArray("argv", mcplib.Required(), mcplib.WithStringItems(),
			mcplib.Description(`Exact binary + args, e.g. ["psql","-c","select 1"]. No shells (sh/bash).`)),
		mcplib.WithObject("env",
			mcplib.Description(`Legacy version-1 env var -> provider ref map`)),
		mcplib.WithArray("secrets", mcplib.WithStringItems(),
			mcplib.Description(`Optional encrypted environment entry names, e.g. ["DATABASE_URL"]`)),
		mcplib.WithString("reason", mcplib.Required(),
			mcplib.Description("Why you need this command — shown to the human reviewer.")),
	)
	s.AddTool(proposeTool, makeProposeHandler(f, policyPath))

	// Tool: list_environments — safe metadata only, never values.
	environmentsTool := mcplib.NewTool("list_environments",
		mcplib.WithDescription("List project environment names, active state, expiry, and configured key counts. Secret values are never returned."),
	)
	s.AddTool(environmentsTool, makeListEnvironmentsHandler(f, policyPath))

	// Tool: request_secret — stage a local, human-fulfilled request. There is no
	// plaintext argument by design; the user enters the value in a masked prompt.
	requestSecretTool := mcplib.NewTool("request_secret",
		mcplib.WithDescription("Ask the user to configure one policy-declared secret through Ironrun's local masked prompt. Never include a secret value in this call."),
		mcplib.WithString("secret_alias", mcplib.Required(),
			mcplib.Description("A secret alias declared in ironrun.yml; this is a name, never a value")),
		mcplib.WithString("reason", mcplib.Required(),
			mcplib.Description("Why the command needs this secret; shown to the user")),
	)
	s.AddTool(requestSecretTool, makeRequestSecretHandler(f, policyPath, sessionID))

	requestLeaseTool := mcplib.NewTool("request_lease",
		mcplib.WithDescription("Request temporary permission for this MCP session to run specific policy commands. A human must approve it locally."),
		mcplib.WithArray("command_ids", mcplib.Required(), mcplib.WithStringItems(),
			mcplib.Description("Policy command IDs requested for this session")),
		mcplib.WithString("ttl", mcplib.Description("Requested lifetime such as 30m or 2h; maximum 24h")),
		mcplib.WithString("reason", mcplib.Required(), mcplib.Description("Why this session needs these commands")),
	)
	s.AddTool(requestLeaseTool, makeRequestLeaseHandler(f, policyPath, sessionID))

	leaseStatusTool := mcplib.NewTool("lease_status",
		mcplib.WithDescription("List this MCP session's lease IDs, scopes, commands, expiry, and revocation state. No secret values are returned."),
	)
	s.AddTool(leaseStatusTool, makeLeaseStatusHandler(policyPath, sessionID))

	revokeLeaseTool := mcplib.NewTool("revoke_own_lease",
		mcplib.WithDescription("Voluntarily revoke one lease belonging to this MCP session."),
		mcplib.WithString("lease_id", mcplib.Required(), mcplib.Description("Lease ID returned by lease_status")),
	)
	s.AddTool(revokeLeaseTool, makeRevokeLeaseHandler(policyPath, sessionID))

	claimCapsuleTool := mcplib.NewTool("claim_capsule",
		mcplib.WithDescription("Claim one Ironrun encrypted capsule created for a pending secret request. The argument is ciphertext, never a plaintext secret."),
		mcplib.WithString("capsule", mcplib.Required(), mcplib.Description("An ir1. encrypted capsule produced by `ironrun capsule create`")),
	)
	s.AddTool(claimCapsuleTool, makeClaimCapsuleHandler(f, policyPath, sessionID))

	return server.ServeStdio(s)
}

func makeRunHandler(f *policy.File, auditLog *audit.Logger, sessionID string, policyPath string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		cmdID := strings.TrimSpace(req.GetString("command_id", ""))
		argv := req.GetStringSlice("argv", nil)
		if (cmdID == "" && len(argv) == 0) || (cmdID != "" && len(argv) != 0) {
			return mcplib.NewToolResultError("provide exactly one of command_id (strict policy mode) or argv (trusted workspace mode)"), nil
		}
		if len(argv) > 0 {
			environment, waitErr := awaitWorkspaceAuthorization(ctx, f, policyPath, sessionID, argv)
			if waitErr != nil {
				return mcplib.NewToolResultError(waitErr.Error()), nil
			}
			res, runErr := executeWorkspace(ctx, projectRoot(policyPath), environment, argv, execution.Options{
				Stdout: os.Stderr, Stderr: os.Stderr, Audit: auditLog, SessionID: sessionID,
			})
			if runErr != nil {
				return mcplib.NewToolResultError(fmt.Sprintf("workspace execution error: %v", runErr)), nil
			}
			return runResult(res), nil
		}
		current, authorizedEnvironment, waitErr := awaitRunAuthorization(ctx, f, policyPath, sessionID, cmdID)
		if waitErr != nil {
			return mcplib.NewToolResultError(waitErr.Error()), nil
		}

		res, runErr := executeCommand(ctx, current, policyPath, projectRoot(policyPath), cmdID, execution.Options{
			Environment: authorizedEnvironment,
			Stdout:      os.Stderr, Stderr: os.Stderr, // redacted live stream
			Audit: auditLog, SessionID: sessionID,
		})
		if runErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("execution error: %v", runErr)), nil
		}

		return runResult(res), nil
	}
}

func runResult(res *runner.Result) *mcplib.CallToolResult {
	truncNote := ""
	if res.Truncated {
		truncNote = "\n[output truncated at max_bytes limit]"
	}
	// Tell the agent (a count only — never the token) if output held a token
	// that looks like a secret but wasn't a registered value.
	entropyNote := ""
	if res.EntropyWarnings > 0 {
		entropyNote = fmt.Sprintf("\n[ironrun] note: %d high-entropy token(s) in the output may be an unredacted secret", res.EntropyWarnings)
	}

	out := fmt.Sprintf(
		"exit_code: %d\nduration_ms: %d%s%s\n\n--- stdout ---\n%s\n--- stderr ---\n%s",
		res.ExitCode,
		res.DurationMs,
		truncNote,
		entropyNote,
		res.Stdout,
		res.Stderr,
	)

	// Non-zero exit is not a tool error — it's a valid result the agent should see.
	return mcplib.NewToolResultText(out)
}

// awaitRunAuthorization turns a blocked sealed run into one persisted human
// request. It never accepts values: the foreground TUI writes masked input
// directly into the encrypted vault, while this loop observes only safe state.
func awaitRunAuthorization(ctx context.Context, startup *policy.File, policyPath, sessionID, commandID string) (*policy.File, string, error) {
	root := projectRoot(policyPath)
	requests, err := access.Open(root)
	if err != nil {
		return nil, "", errors.New("local access state is unavailable")
	}
	tracked := map[string]bool{}
	var waitUntil time.Time
	wasProposed := false
	for {
		for id := range tracked {
			request, requestErr := requests.Request(id)
			if requestErr == nil && (request.Status == access.StatusDenied || request.Status == access.StatusExpired) {
				return nil, "", fmt.Errorf("sealed run %s: request %s was %s", commandID, id, request.Status)
			}
		}
		if !waitUntil.IsZero() && !time.Now().Before(waitUntil) {
			return nil, "", fmt.Errorf("sealed run %s: human approval request expired", commandID)
		}

		current, reloadErr := currentPolicy(startup, policyPath)
		if reloadErr != nil {
			return nil, "", fmt.Errorf("policy reload failed: %v", reloadErr)
		}
		pCmd, lookupErr := current.Lookup(commandID)
		if lookupErr != nil {
			proposals, loadErr := pending.Load(pending.Path(policyPath))
			if loadErr != nil {
				return nil, "", errors.New("pending command state is unavailable")
			}
			if proposals.Find(commandID) == nil {
				if wasProposed {
					return nil, "", fmt.Errorf("command %q was rejected or removed before approval", commandID)
				}
				hint := fmt.Sprintf("command %q not found in policy.", commandID)
				if current.AllowProposals {
					hint += " Call propose_command with the exact argv; run_sealed will wait and resume after human approval."
				}
				return nil, "", errors.New(hint)
			}
			wasProposed = true
			if waitUntil.IsZero() {
				waitUntil = time.Now().Add(access.DefaultRequestTTL)
			}
			if err := waitForChange(ctx); err != nil {
				return nil, "", fmt.Errorf("sealed run %s cancelled while waiting for command approval", commandID)
			}
			continue
		}

		environment, envErr := resolveExecutionEnvironment(current, policyPath)
		if envErr != nil {
			return nil, "", errors.New("project environment is unavailable")
		}
		missing, secretRequests, secretErr := requestMissingSecrets(current, pCmd, policyPath, sessionID, environment, requests)
		if secretErr != nil {
			return nil, "", secretErr
		}
		for _, request := range secretRequests {
			tracked[request.ID] = true
			if waitUntil.IsZero() || request.ExpiresAt.Before(waitUntil) {
				waitUntil = request.ExpiresAt
			}
		}

		leaseReady := true
		if current.RequireAgentLeases {
			if authErr := requests.Authorize(sessionID, environment, commandID); authErr != nil {
				leaseReady = false
				request, createErr := requests.CreateLeaseRequest(sessionID, environment, []string{commandID}, access.DefaultLeaseTTL, "run_sealed is waiting for human review")
				if createErr != nil {
					return nil, "", fmt.Errorf("could not create lease request: %v", createErr)
				}
				tracked[request.ID] = true
				if waitUntil.IsZero() || request.ExpiresAt.Before(waitUntil) {
					waitUntil = request.ExpiresAt
				}
			}
		}
		if !missing && leaseReady {
			// Environment remains pinned from the authorization check through
			// execution even if another user action changes the active set.
			pinnedEnvironment := environment
			if !current.UsesEnvironmentEntries() && current.EnvironmentSet != "active" {
				pinnedEnvironment = ""
			}
			return current, pinnedEnvironment, nil
		}
		if err := waitForChange(ctx); err != nil {
			return nil, "", fmt.Errorf("sealed run %s cancelled while waiting for human review", commandID)
		}
	}
}

// awaitWorkspaceAuthorization creates exactly one human-reviewable request for
// an arbitrary argv attempt, then waits for an active grant bound to this MCP
// server process. It intentionally never reads or receives secret values.
func awaitWorkspaceAuthorization(ctx context.Context, startup *policy.File, policyPath, sessionID string, argv []string) (string, error) {
	root := projectRoot(policyPath)
	requests, err := access.Open(root)
	if err != nil {
		return "", errors.New("local access state is unavailable")
	}
	current, err := currentPolicy(startup, policyPath)
	if err != nil {
		return "", errors.New("policy reload failed")
	}
	environment, err := resolveExecutionEnvironment(current, policyPath)
	if err != nil {
		return "", errors.New("project environment is unavailable")
	}
	if _, authErr := requests.AuthorizeWorkspace(sessionID, environment); authErr == nil {
		return environment, nil
	}
	request, err := requests.CreateWorkspaceRequest(sessionID, environment, argv, access.DefaultWorkspaceTTL, "agent requested trusted workspace access")
	if err != nil {
		return "", fmt.Errorf("could not create workspace access request: %v", err)
	}
	for {
		if request.Status == access.StatusDenied || request.Status == access.StatusExpired {
			return "", fmt.Errorf("trusted workspace request %s was %s", request.ID, request.Status)
		}
		if _, authErr := requests.AuthorizeWorkspace(sessionID, environment); authErr == nil {
			return environment, nil
		}
		if !time.Now().Before(request.ExpiresAt) {
			return "", errors.New("trusted workspace request expired")
		}
		if err := waitForChange(ctx); err != nil {
			return "", errors.New("workspace run cancelled while waiting for human trust")
		}
		request, _ = requests.Request(request.ID)
	}
}

func makeRequestWorkspaceHandler(f *policy.File, policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		reason, err := req.RequireString("reason")
		if err != nil {
			return mcplib.NewToolResultError("reason is required"), nil
		}
		current, err := currentPolicy(f, policyPath)
		if err != nil {
			return mcplib.NewToolResultError("policy reload failed"), nil
		}
		environment, err := resolveExecutionEnvironment(current, policyPath)
		if err != nil {
			return mcplib.NewToolResultError("project environment is unavailable"), nil
		}
		argv := req.GetStringSlice("argv", nil)
		if len(argv) == 0 {
			argv = []string{"(agent workspace request)"}
		}
		manager, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		request, err := manager.CreateWorkspaceRequest(sessionID, environment, argv, access.DefaultWorkspaceTTL, reason)
		if err != nil {
			return mcplib.NewToolResultError("could not create trusted workspace request"), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf("Trusted workspace request %s is pending for environment %q. A human can approve it in Ironrun's Agent Access screen or with `ironrun trust grant %s`. The request expires in %s.", request.ID, environment, request.ID, access.DefaultWorkspaceTTL)), nil
	}
}

func makeWorkspaceStatusHandler(policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		root := projectRoot(policyPath)
		manager, err := envset.Open(root)
		if err != nil {
			return mcplib.NewToolResultError("environment store unavailable"), nil
		}
		active, err := manager.Active()
		if err != nil {
			return mcplib.NewToolResultError("no selected environment"), nil
		}
		keys := make([]string, 0, len(active.Entries))
		for _, entry := range active.Entries {
			keys = append(keys, entry.Name)
		}
		requests, err := access.Open(root)
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		status := "not trusted"
		if grant, authErr := requests.AuthorizeWorkspace(sessionID, active.Name); authErr == nil {
			status = fmt.Sprintf("trusted until %s (normal network)", grant.ExpiresAt.Local().Format(time.RFC3339))
		}
		return mcplib.NewToolResultText(fmt.Sprintf("Project: %s\nEnvironment: %s\nConfigured entries: %s\nSession: %s", root, active.Name, strings.Join(keys, ", "), status)), nil
	}
}

func requestMissingSecrets(f *policy.File, command *policy.Command, policyPath, sessionID, environment string, requests *access.Manager) (bool, []access.Request, error) {
	if len(command.Secrets) == 0 {
		return false, nil, nil
	}
	root := projectRoot(policyPath)
	var environments *envset.Manager
	if f.UsesEnvironmentEntries() || f.EnvironmentSet == "active" {
		var err error
		environments, err = envset.Open(root)
		if err != nil {
			return false, nil, errors.New("encrypted environment is unavailable")
		}
	}
	missing := false
	var created []access.Request
	for _, name := range command.Secrets {
		key, storeName, ok := f.SecretBinding(name)
		if !ok {
			return false, nil, fmt.Errorf("policy secret binding %q is invalid", name)
		}
		configured := false
		if environments != nil {
			entry, exists := environments.Entry(environment, key)
			if exists {
				if entry.Kind == envset.EntryFile {
					_, err := environments.GetBytes(environment, key)
					configured = err == nil
				} else {
					_, err := environments.Get(environment, key)
					configured = err == nil
				}
			}
		} else {
			store, err := secretstore.Open(policyPath, storeName)
			if err != nil {
				return false, nil, fmt.Errorf("secret store for %q is unavailable", name)
			}
			_, err = store.Get(name)
			configured = err == nil
		}
		if configured {
			continue
		}
		missing = true
		request, err := requests.CreateSecretRequestForCommands(sessionID, environment, name, key, []string{command.ID}, "run_sealed is waiting for this encrypted value")
		if err != nil {
			return false, nil, fmt.Errorf("could not create secret request for %q", name)
		}
		created = append(created, request)
	}
	return missing, created, nil
}

func waitForChange(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func currentPolicy(f *policy.File, policyPath string) (*policy.File, error) {
	if strings.TrimSpace(policyPath) == "" {
		return f, nil
	}
	return policy.Load(policyPath)
}

func makeListEnvironmentsHandler(f *policy.File, policyPath string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		current, reloadErr := currentPolicy(f, policyPath)
		if reloadErr != nil {
			return mcplib.NewToolResultError("policy reload failed"), nil
		}
		if !current.UsesEnvironmentEntries() && current.EnvironmentSet != "active" {
			return mcplib.NewToolResultText("Environments:\n  * default (provider/alias storage; values hidden)"), nil
		}
		manager, err := envset.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("environment store unavailable"), nil
		}
		var out strings.Builder
		out.WriteString("Environments:\n")
		for _, name := range manager.Names() {
			set, _ := manager.Set(name)
			marker := " "
			if name == manager.Meta.Active {
				marker = "*"
			}
			status := "active"
			if manager.Expired(set) {
				status = "expired"
			}
			fmt.Fprintf(&out, "  %s %s: %s, configured_items=%d", marker, name, status, len(set.Entries))
			if set.ExpiresAt != nil {
				fmt.Fprintf(&out, ", expires=%s", set.ExpiresAt.UTC().Format(time.RFC3339))
			}
			out.WriteByte('\n')
			for _, entry := range set.Entries {
				fmt.Fprintf(&out, "      %s (%s -> %s", entry.Name, entry.Kind, entry.Target)
				if entry.Filename != "" {
					fmt.Fprintf(&out, ", file=%s", entry.Filename)
				}
				out.WriteString(")\n")
			}
		}
		return mcplib.NewToolResultText(strings.TrimRight(out.String(), "\n")), nil
	}
}

func makeRequestSecretHandler(f *policy.File, policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		alias, err := req.RequireString("secret_alias")
		if err != nil {
			return mcplib.NewToolResultError("secret_alias is required"), nil
		}
		key, _, ok := f.SecretBinding(alias)
		if !ok {
			return mcplib.NewToolResultError("secret alias is not declared in the policy"), nil
		}
		environment, err := executionEnvironment(f, policyPath)
		if err != nil {
			return mcplib.NewToolResultError("project environment is unavailable"), nil
		}
		manager, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		request, err := manager.CreateSecretRequest(sessionID, environment, alias, key, mustString(req, "reason"))
		if err != nil {
			return mcplib.NewToolResultError("could not create secret request"), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf(
			"Secret request %s is pending for alias %q in environment %q. No value was accepted or exposed. Ask the user to run `ironrun access fulfill %s` locally, or `ironrun capsule create %s` to produce one-use ciphertext that can be pasted into chat and claimed with claim_capsule.",
			request.ID, alias, environment, request.ID, request.ID)), nil
	}
}

func makeRequestLeaseHandler(f *policy.File, policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		commands, err := req.RequireStringSlice("command_ids")
		if err != nil || len(commands) == 0 {
			return mcplib.NewToolResultError("command_ids must be a non-empty array"), nil
		}
		for _, command := range commands {
			if _, err := f.Lookup(command); err != nil {
				return mcplib.NewToolResultError(fmt.Sprintf("command %q is not in the policy", command)), nil
			}
		}
		ttl := access.DefaultLeaseTTL
		if raw := strings.TrimSpace(mustString(req, "ttl")); raw != "" {
			ttl, err = time.ParseDuration(raw)
			if err != nil || ttl <= 0 {
				return mcplib.NewToolResultError("ttl must be a positive duration such as 30m or 2h"), nil
			}
		}
		environment, err := executionEnvironment(f, policyPath)
		if err != nil {
			return mcplib.NewToolResultError("project environment is unavailable"), nil
		}
		manager, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		request, err := manager.CreateLeaseRequest(sessionID, environment, commands, ttl, mustString(req, "reason"))
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("could not create lease request: %v", err)), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf(
			"Lease request %s is pending for environment %q and commands %v (requested ttl %s). Ask the user to run `ironrun access approve %s` locally. The commands remain blocked until approval.",
			request.ID, environment, request.Commands, request.RequestedTTL, request.ID)), nil
	}
}

func makeLeaseStatusHandler(policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		manager, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		leases, err := manager.Leases(sessionID)
		if err != nil {
			return mcplib.NewToolResultError("could not read lease status"), nil
		}
		if len(leases) == 0 {
			return mcplib.NewToolResultText("No leases exist for this MCP session."), nil
		}
		var out strings.Builder
		for _, lease := range leases {
			status := "active"
			if lease.RevokedAt != nil {
				status = "revoked"
			} else if !time.Now().UTC().Before(lease.ExpiresAt) {
				status = "expired"
			}
			fmt.Fprintf(&out, "%s: %s environment=%s commands=%v expires=%s\n", lease.ID, status, lease.Environment, lease.Commands, lease.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return mcplib.NewToolResultText(strings.TrimRight(out.String(), "\n")), nil
	}
}

func makeRevokeLeaseHandler(policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id, err := req.RequireString("lease_id")
		if err != nil {
			return mcplib.NewToolResultError("lease_id is required"), nil
		}
		manager, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		if err := manager.Revoke(id, sessionID); err != nil {
			return mcplib.NewToolResultError("lease not found for this MCP session"), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf("Lease %s revoked. It cannot authorize another command.", id)), nil
	}
}

func makeClaimCapsuleHandler(f *policy.File, policyPath, sessionID string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		sealed, err := req.RequireString("capsule")
		if err != nil || !strings.HasPrefix(sealed, "ir1.") {
			return mcplib.NewToolResultError("a valid encrypted capsule is required"), nil
		}
		capsules, err := capsule.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local capsule key is unavailable"), nil
		}
		payload, err := capsules.Open(sealed)
		if err != nil || payload.SessionID != sessionID {
			return mcplib.NewToolResultError("capsule is invalid, expired, or belongs to another session"), nil
		}
		requests, err := access.Open(projectRoot(policyPath))
		if err != nil {
			return mcplib.NewToolResultError("local access state is unavailable"), nil
		}
		request, err := requests.Request(payload.RequestID)
		if err != nil || request.Kind != access.RequestSecret || request.Status != access.StatusPending ||
			request.SessionID != sessionID || request.Environment != payload.Environment ||
			request.SecretAlias != payload.SecretAlias || request.SecretKey != payload.SecretKey {
			return mcplib.NewToolResultError("capsule request is no longer pending or does not match this session"), nil
		}
		key, storeName, ok := f.SecretBinding(request.SecretAlias)
		if !ok || key != request.SecretKey {
			return mcplib.NewToolResultError("capsule request no longer matches the policy"), nil
		}
		if _, err := requests.FulfillSecretWith(request.ID, func(locked access.Request) error {
			if f.UsesEnvironmentEntries() || f.EnvironmentSet == "active" {
				environments, err := envset.Open(projectRoot(policyPath))
				if err != nil {
					return err
				}
				return environments.Put(locked.Environment, locked.SecretKey, payload.Value)
			}
			store, err := secretstore.Open(policyPath, storeName)
			if err != nil {
				return err
			}
			return store.Set(locked.SecretAlias, payload.Value)
		}); err != nil {
			return mcplib.NewToolResultError("capsule claim failed or was already consumed"), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf(
			"Capsule claimed for alias %q in environment %q. The plaintext was decrypted and stored locally and was never returned through MCP. This request cannot be replayed.",
			request.SecretAlias, request.Environment)), nil
	}
}

func executionEnvironment(f *policy.File, policyPath string) (string, error) {
	if !f.UsesEnvironmentEntries() && f.EnvironmentSet != "active" {
		return "default", nil
	}
	manager, err := envset.Open(projectRoot(policyPath))
	if err != nil {
		return "", err
	}
	active, err := manager.Active()
	if err != nil {
		return "", err
	}
	return active.Name, nil
}

func projectRoot(policyPath string) string {
	abs, err := filepath.Abs(policyPath)
	if err != nil {
		return mustCwd()
	}
	return filepath.Dir(abs)
}

func mustCwd() string { cwd, _ := os.Getwd(); return cwd }

// makeProposeHandler stages an agent-proposed command into .ironrun/pending.yml.
// It NEVER runs anything and NEVER writes ironrun.yml — only `ironrun approve`
// (a human action in the terminal) can promote a proposal into the policy.
func makeProposeHandler(f *policy.File, policyPath string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		if !f.AllowProposals {
			return mcplib.NewToolResultError("command proposals are disabled. Ask the user to set `allow_proposals: true` in ironrun.yml to enable propose_command."), nil
		}
		id := strings.TrimSpace(mustString(req, "id"))
		if !validProposalID(id) {
			return mcplib.NewToolResultError("id must be non-empty and contain only letters, digits, '-' and '_'"), nil
		}
		argv, err := req.RequireStringSlice("argv")
		if err != nil || len(argv) == 0 {
			return mcplib.NewToolResultError(`argv is required (a non-empty array, e.g. ["psql","-c","select 1"])`), nil
		}
		if policy.IsShellString(argv) {
			return mcplib.NewToolResultError("shell commands cannot be proposed (no sh/bash/zsh). Propose the real binary and its arguments directly."), nil
		}
		reason := strings.TrimSpace(mustString(req, "reason"))
		if reason == "" {
			return mcplib.NewToolResultError("reason is required — explain why you need this command (the user sees it when reviewing)"), nil
		}
		if _, lerr := f.Lookup(id); lerr == nil {
			return mcplib.NewToolResultError(fmt.Sprintf("%q already exists in the policy — just call run_sealed with it.", id)), nil
		}

		path := pending.Path(policyPath)
		store, err := pending.Load(path)
		if err != nil {
			return mcplib.NewToolResultError("could not read the pending store"), nil
		}
		proposalEnv := coerceEnv(req.GetArguments()["env"])
		if current, reloadErr := currentPolicy(f, policyPath); reloadErr == nil && current.UsesEnvironmentEntries() {
			for _, name := range optionalStringSlice(req, "secrets") {
				if proposalEnv == nil {
					proposalEnv = map[string]string{}
				}
				proposalEnv[name] = name
			}
		}
		store.Upsert(pending.Proposal{
			ID:         id,
			Argv:       argv,
			Env:        proposalEnv,
			Reason:     reason,
			ProposedAt: time.Now().UTC().Format(time.RFC3339), // server-side; agent time is untrusted
			Status:     "pending",
		})
		if err := pending.Save(path, store); err != nil {
			return mcplib.NewToolResultError("could not save the proposal"), nil
		}
		return mcplib.NewToolResultText(fmt.Sprintf(
			"Proposed %q. It is NOT yet runnable. A human must run `ironrun approve %s` in their terminal; you can run_sealed with %q only after they approve.",
			id, id, id)), nil
	}
}

func optionalStringSlice(req mcplib.CallToolRequest, key string) []string {
	values, err := req.RequireStringSlice(key)
	if err != nil {
		return nil
	}
	return values
}

func mustString(req mcplib.CallToolRequest, key string) string {
	s, _ := req.RequireString(key)
	return s
}

func validProposalID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func coerceEnv(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
