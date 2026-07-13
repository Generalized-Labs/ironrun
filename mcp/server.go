// Package mcp exposes ironrun as an MCP stdio server.
// AI agents (Claude Code, Cursor, any MCP host) can call run_sealed to execute
// policy-authorized commands without receiving raw secret values.
package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/buildinfo"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/pending"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
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

	return server.ServeStdio(s)
}

func makeRunHandler(f *policy.File, auditLog *audit.Logger, sessionID string, policyPath string) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		cmdID, err := req.RequireString("command_id")
		if err != nil {
			return mcplib.NewToolResultError("command_id is required"), nil
		}

		pCmd, err := f.Lookup(cmdID)
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

		p, err := provider.New(f.Provider)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("provider error: %v", err)), nil
		}

		resolved, err := provider.ResolveAll(p, pCmd.Env)
		if err != nil {
			// Don't expose which secret failed in detail — just say resolution failed.
			return mcplib.NewToolResultError("secret resolution failed — check provider configuration"), nil
		}

		if len(pCmd.Secrets) > 0 && f.EnvironmentSet == "active" {
			manager, managerErr := envset.Open(mustCwd())
			if managerErr != nil {
				return mcplib.NewToolResultError("environment store unavailable"), nil
			}
			active, activeErr := manager.Active()
			if activeErr != nil {
				return mcplib.NewToolResultError("environment set unavailable"), nil
			}
			for _, alias := range pCmd.Secrets {
				decl := f.Secrets[alias]
				value, getErr := manager.Get(active.Name, decl.Env)
				if getErr != nil {
					return mcplib.NewToolResultError("secret resolution failed — check environment status"), nil
				}
				resolved[decl.Env] = value
			}
		} else if len(pCmd.Secrets) > 0 {
			aliases, aliasErr := secretstore.ResolveAliasesWithOpener(f, pCmd, func(requested string) (secretstore.Store, error) {
				return secretstore.Open(policyPath, requested)
			})
			if aliasErr != nil {
				return mcplib.NewToolResultError("secret resolution failed — check secret onboarding"), nil
			}
			for k, v := range aliases {
				resolved[k] = v
			}
		}

		seccompOn := pCmd.SeccompEnabled(f) && os.Getenv("IRONRUN_SECCOMP") != "off"
		res, runErr := runner.Run(ctx, pCmd, runner.Options{
			Stdout:    os.Stderr, // live stream to stderr (agent won't see it)
			Stderr:    os.Stderr,
			Secrets:   resolved,
			Seccomp:   &seccompOn,
			Audit:     auditLog,
			SessionID: sessionID,
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
