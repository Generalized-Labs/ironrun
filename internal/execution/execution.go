// Package execution is the shared sealed-run path for CLI, MCP, and local API
// callers. Authorization remains the caller's responsibility; secret
// resolution, injection, redaction, sandbox controls, and audit are centralized.
package execution

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
	"github.com/generalized-labs/ironrun/internal/secrets"
)

type Options struct {
	Environment string
	Stdout      io.Writer
	Stderr      io.Writer
	Audit       *audit.Logger
	SessionID   string
}

func Run(ctx context.Context, f *policy.File, policyPath, root, commandID string, opts Options) (*runner.Result, error) {
	pCmd, err := f.Lookup(commandID)
	if err != nil {
		return nil, err
	}
	p, err := provider.New(f.Provider)
	if err != nil {
		return nil, err
	}
	resolved, err := provider.ResolveAll(p, pCmd.Env)
	if err != nil {
		return nil, fmt.Errorf("secret resolution failed: %w", err)
	}
	if len(pCmd.Secrets) > 0 {
		if opts.Environment != "" || f.EnvironmentSet == "active" {
			manager, err := envset.Open(root)
			if err != nil {
				return nil, fmt.Errorf("environment store unavailable: %w", err)
			}
			selected := opts.Environment
			if selected == "" {
				active, err := manager.Active()
				if err != nil {
					return nil, fmt.Errorf("environment set unavailable: %w", err)
				}
				selected = active.Name
			}
			for _, alias := range pCmd.Secrets {
				decl := f.Secrets[alias]
				value, err := manager.Get(selected, decl.Env)
				if err != nil {
					return nil, fmt.Errorf("secret resolution failed: environment key %q is unavailable", decl.Env)
				}
				resolved[decl.Env] = value
			}
		} else {
			aliases, err := secrets.ResolveAliasesWithOpener(f, pCmd, func(requested string) (secrets.Store, error) {
				return secrets.Open(policyPath, requested)
			})
			if err != nil {
				return nil, fmt.Errorf("secret resolution failed: %w", err)
			}
			for key, value := range aliases {
				resolved[key] = value
			}
		}
	}
	seccompOn := pCmd.SeccompEnabled(f) && os.Getenv("IRONRUN_SECCOMP") != "off"
	return runner.Run(ctx, pCmd, runner.Options{
		Stdout: opts.Stdout, Stderr: opts.Stderr, WorkDir: root,
		Secrets: resolved, Seccomp: &seccompOn, Audit: opts.Audit, SessionID: opts.SessionID,
	})
}
