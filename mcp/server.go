// Package mcp exposes ironrun as an MCP stdio server.
// AI agents (Claude Code, Cursor, any MCP host) can call run_sealed to execute
// policy-authorized commands without receiving raw secret values.
package mcp

import (
	"context"
	"fmt"
	"os"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/generalized-labs/ironrun/internal/buildinfo"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
)

// Serve starts the MCP stdio server using the given policy.
// It blocks until the client disconnects or the process exits.
func Serve(f *policy.File) error {
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
	s.AddTool(runTool, makeRunHandler(f))

	// Tool: validate_policy — sanity-check the loaded policy.
	validateTool := mcplib.NewTool("validate_policy",
		mcplib.WithDescription("Validate the current policy file and return a summary of defined commands."),
	)
	s.AddTool(validateTool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		out := fmt.Sprintf("Policy OK: %d command(s), provider=%s\n", len(f.Commands), f.Provider)
		return mcplib.NewToolResultText(out), nil
	})

	return server.ServeStdio(s)
}

func makeRunHandler(f *policy.File) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		cmdID, err := req.RequireString("command_id")
		if err != nil {
			return mcplib.NewToolResultError("command_id is required"), nil
		}

		pCmd, err := f.Lookup(cmdID)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("command %q not found in policy", cmdID)), nil
		}

		p, err := provider.New(f.Provider)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("provider error: %v", err)), nil
		}

		secrets, err := provider.ResolveAll(p, pCmd.Env)
		if err != nil {
			// Don't expose which secret failed in detail — just say resolution failed.
			return mcplib.NewToolResultError("secret resolution failed — check provider configuration"), nil
		}

		res, runErr := runner.Run(ctx, pCmd, runner.Options{
			Stdout:  os.Stderr, // live stream to stderr (agent won't see it)
			Stderr:  os.Stderr,
			Secrets: secrets,
		})
		if runErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("execution error: %v", runErr)), nil
		}

		truncNote := ""
		if res.Truncated {
			truncNote = "\n[output truncated at max_bytes limit]"
		}

		out := fmt.Sprintf(
			"exit_code: %d\nduration_ms: %d%s\n\n--- stdout ---\n%s\n--- stderr ---\n%s",
			res.ExitCode,
			res.DurationMs,
			truncNote,
			res.Stdout,
			res.Stderr,
		)

		// Non-zero exit is not a tool error — it's a valid result the agent should see.
		return mcplib.NewToolResultText(out), nil
	}
}
