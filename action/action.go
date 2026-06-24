// Package action implements the GitHub Actions entrypoint for ironrun.
// When run inside GitHub Actions, it reads inputs from environment variables
// (INPUT_* per the GHA convention), executes the sealed command, and sets
// output variables for downstream steps.
//
// Usage in a workflow step:
//
//   - uses: generalized-labs/ironrun@v1
//     with:
//     command_id: test
//     policy: ironrun.yml
package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
)

// Run is the GitHub Actions entrypoint. Returns exit code.
func Run() int {
	commandID := ghaInput("command_id")
	policyPath := ghaInput("policy")
	if policyPath == "" {
		policyPath = "ironrun.yml"
	}

	// Resolve policy path relative to GITHUB_WORKSPACE if set.
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" && !filepath.IsAbs(policyPath) {
		policyPath = filepath.Join(ws, policyPath)
	}

	if commandID == "" {
		ghaError("input 'command_id' is required")
		return 1
	}

	f, err := policy.Load(policyPath)
	if err != nil {
		ghaError("policy load failed: " + err.Error())
		return 1
	}

	cmd, err := f.Lookup(commandID)
	if err != nil {
		ghaError(err.Error())
		return 1
	}

	p, err := provider.New(f.Provider)
	if err != nil {
		ghaError("provider error: " + err.Error())
		return 1
	}

	secrets, err := provider.ResolveAll(p, cmd.Env)
	if err != nil {
		ghaError("secret resolution failed (check provider config)")
		return 1
	}

	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Secrets: secrets,
	})
	if err != nil {
		ghaError("execution failed: " + err.Error())
		return 1
	}

	// Set GHA outputs.
	ghaSetOutput("exit_code", fmt.Sprintf("%d", res.ExitCode))
	ghaSetOutput("duration_ms", fmt.Sprintf("%d", res.DurationMs))
	ghaSetOutput("redactions", fmt.Sprintf("%d", res.RedactionCount))
	if res.Truncated {
		ghaSetOutput("truncated", "true")
	} else {
		ghaSetOutput("truncated", "false")
	}

	if res.ExitCode != 0 {
		ghaError(fmt.Sprintf("command %q exited with code %d", commandID, res.ExitCode))
	}

	return res.ExitCode
}

// ghaInput reads a GitHub Actions input (INPUT_<NAME> env var).
func ghaInput(name string) string {
	key := "INPUT_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return strings.TrimSpace(os.Getenv(key))
}

// ghaSetOutput writes a step output using the GITHUB_OUTPUT file.
func ghaSetOutput(name, value string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		// Fallback: old ::set-output syntax (deprecated but harmless).
		fmt.Printf("::set-output name=%s::%s\n", name, value)
		return
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s=%s\n", name, value)
}

// ghaError writes a GHA error annotation to stdout.
func ghaError(msg string) {
	fmt.Printf("::error::%s\n", msg)
}
