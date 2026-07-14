// Package mcp exposes ironrun as an MCP stdio server.
// AI agents (Claude Code, Cursor, any MCP host) can call run_sealed to execute
// policy-authorized commands without receiving raw secret values.
package mcp

import (
	"context"
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
	secretstore "github.com/generalized-labs/ironrun/internal/secrets"
)

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
		out := "Available commands:\n"
		for _, cmd := range f.Commands {
			out += fmt.Sprintf("  • %s: %v\n", cmd.ID, cmd.Argv)
		}
		return mcplib.NewToolResultText(out), nil
	})

	// Tool: run_sealed — execute a command by ID, returning redacted output.
	runTool := mcplib.NewTool("run_sealed",
		mcplib.WithDescription(
			"Execute a policy-authorized command by its ID. "+
				"Secrets are injected below agent visibility and redacted from all output. "+
				"The agent never sees raw secret values.",
		),
		mcplib.WithString("command_id",
			mcplib.Required(),
			mcplib.Description("The policy command ID to execute (use list_commands to discover IDs)"),
		),
	)
	s.AddTool(runTool, makeRunHandler(f, auditLog, sessionID, policyPath))

	// Tool: validate_policy — sanity-check the loaded policy.
	validateTool := mcplib.NewTool("validate_policy",
		mcplib.WithDescription("Validate the current policy file and return a summary of defined commands."),
	)
	s.AddTool(validateTool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		out := fmt.Sprintf("Policy OK: %d command(s), provider=%s\n", len(f.Commands), f.Provider)
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
			mcplib.Description(`Optional env var -> secret ref map, e.g. {"DATABASE_URL":"env:DATABASE_URL"}`)),
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
		cmdID, err := req.RequireString("command_id")
		if err != nil {
			return mcplib.NewToolResultError("command_id is required"), nil
		}

		_, err = f.Lookup(cmdID)
		if err != nil {
			// Not in the policy — NEVER execute. run_sealed only ever resolves
			// through the loaded policy; a pending proposal is never dispatchable.
			if st, lerr := pending.Load(pending.Path(policyPath)); lerr == nil && st.Find(cmdID) != nil {
				return mcplib.NewToolResultError(fmt.Sprintf(
					"%q is proposed but awaiting human approval. Ask the user to run `ironrun approve %s` in their terminal, then retry. ironrun will not run an unapproved command.",
					cmdID, cmdID)), nil
			}
			hint := fmt.Sprintf("command %q not found in policy.", cmdID)
			if f.AllowProposals {
				hint += " If you need it, call propose_command to stage it for the user's approval — do not run it in a shell."
			}
			return mcplib.NewToolResultError(hint), nil
		}
		if f.RequireAgentLeases {
			environment, envErr := executionEnvironment(f, policyPath)
			if envErr != nil {
				return mcplib.NewToolResultError("agent lease check failed — project environment is unavailable"), nil
			}
			manager, accessErr := access.Open(projectRoot(policyPath))
			if accessErr != nil {
				return mcplib.NewToolResultError("agent lease check failed — local access state is unavailable"), nil
			}
			if accessErr := manager.Authorize(sessionID, environment, cmdID); accessErr != nil {
				return mcplib.NewToolResultError(fmt.Sprintf(
					"agent lease required for command %q in environment %q. Call request_lease, then ask the user to approve it locally.",
					cmdID, environment)), nil
			}
		}

		res, runErr := execution.Run(ctx, f, policyPath, projectRoot(policyPath), cmdID, execution.Options{
			Stdout: os.Stderr, Stderr: os.Stderr, // redacted live stream
			Audit: auditLog, SessionID: sessionID,
		})
		if runErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("execution error: %v", runErr)), nil
		}

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
		return mcplib.NewToolResultText(out), nil
	}
}

func makeListEnvironmentsHandler(f *policy.File, policyPath string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		if f.EnvironmentSet != "active" {
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
			fmt.Fprintf(&out, "  %s %s: %s, configured_keys=%d", marker, name, status, len(set.Keys))
			if set.ExpiresAt != nil {
				fmt.Fprintf(&out, ", expires=%s", set.ExpiresAt.UTC().Format(time.RFC3339))
			}
			out.WriteByte('\n')
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
		decl, ok := f.Secrets[alias]
		if !ok || decl.Env == "" {
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
		request, err := manager.CreateSecretRequest(sessionID, environment, alias, decl.Env, mustString(req, "reason"))
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
		decl, ok := f.Secrets[request.SecretAlias]
		if !ok || decl.Env != request.SecretKey {
			return mcplib.NewToolResultError("capsule request no longer matches the policy"), nil
		}
		if _, err := requests.FulfillSecretWith(request.ID, func(locked access.Request) error {
			if f.EnvironmentSet == "active" {
				environments, err := envset.Open(projectRoot(policyPath))
				if err != nil {
					return err
				}
				return environments.Put(locked.Environment, locked.SecretKey, payload.Value)
			}
			store, err := secretstore.Open(policyPath, decl.Store)
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
	if f.EnvironmentSet != "active" {
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
		store.Upsert(pending.Proposal{
			ID:         id,
			Argv:       argv,
			Env:        coerceEnv(req.GetArguments()["env"]),
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
