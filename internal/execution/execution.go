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
	var files *fileWorkspace
	var redactValues []string
	var auditSecrets []audit.SecretUse
	defer func() { _ = files.Close() }()
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
				auditSecrets = append(auditSecrets, audit.SecretUse{Name: alias, Kind: decl.EffectiveKind(), Target: decl.Env})
				if decl.EffectiveKind() == "file" {
					entry, ok := manager.Entry(selected, decl.Env)
					if !ok || entry.Kind != envset.EntryFile {
						return nil, fmt.Errorf("secret resolution failed: %q is not configured as a file secret", decl.Env)
					}
					value, err := manager.GetBytes(selected, decl.Env)
					if err != nil {
						return nil, fmt.Errorf("secret resolution failed: file secret %q is unavailable", decl.Env)
					}
					if files == nil {
						files, err = newFileWorkspace()
						if err != nil {
							return nil, fmt.Errorf("file secret workspace unavailable: %w", err)
						}
					}
					path, err := files.Materialize(decl.Filename, value)
					if err != nil {
						return nil, err
					}
					resolved[decl.Env] = path
					redactValues = append(redactValues, string(value))
				} else {
					value, err := manager.Get(selected, decl.Env)
					if err != nil {
						return nil, fmt.Errorf("secret resolution failed: environment key %q is unavailable", decl.Env)
					}
					resolved[decl.Env] = value
				}
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
	var cleanup func() error
	if files != nil {
		cleanup = files.Close
	}
	return runner.Run(ctx, pCmd, runner.Options{
		Stdout: opts.Stdout, Stderr: opts.Stderr, WorkDir: root,
		Secrets: resolved, RedactValues: redactValues, AuditSecrets: auditSecrets, Seccomp: &seccompOn, Audit: opts.Audit, SessionID: opts.SessionID,
		Cleanup: cleanup,
	})
}
