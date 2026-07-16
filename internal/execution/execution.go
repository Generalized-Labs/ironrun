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
	// AllowShell is true only for an already authorized trusted workspace
	// session. Strict policy execution never enables it.
	AllowShell bool
}

var openEnvironment = envset.Open

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
		if f.UsesEnvironmentEntries() || opts.Environment != "" || f.EnvironmentSet == "active" {
			manager, err := openEnvironment(root)
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
				entryName := alias
				entry, ok := manager.Entry(selected, entryName)
				if f.UsesEnvironmentEntries() {
					if !ok {
						return nil, fmt.Errorf("secret resolution failed: environment entry %q is unavailable", entryName)
					}
				} else {
					decl := f.Secrets[alias]
					entryName = decl.Env
					entry, ok = manager.Entry(selected, entryName)
					if !ok {
						return nil, fmt.Errorf("secret resolution failed: environment entry %q is unavailable", entryName)
					}
					// Version-1 declarations remain authoritative for target and
					// filename so existing policies retain their exact behavior.
					entry.Kind = envset.EntryKind(decl.EffectiveKind())
					entry.Target = decl.Env
					entry.Filename = decl.Filename
				}
				auditSecrets = append(auditSecrets, audit.SecretUse{Name: alias, Kind: string(entry.Kind), Target: entry.Target})
				if entry.Kind == envset.EntryFile {
					if entry.Filename == "" {
						return nil, fmt.Errorf("secret resolution failed: file secret %q has no safe filename", entryName)
					}
					entry, ok := manager.Entry(selected, entryName)
					if !ok || entry.Kind != envset.EntryFile {
						return nil, fmt.Errorf("secret resolution failed: %q is not configured as a file secret", entryName)
					}
					value, err := manager.GetBytes(selected, entryName)
					if err != nil {
						return nil, fmt.Errorf("secret resolution failed: file secret %q is unavailable", entryName)
					}
					if files == nil {
						files, err = newFileWorkspace()
						if err != nil {
							return nil, fmt.Errorf("file secret workspace unavailable: %w", err)
						}
					}
					path, err := files.Materialize(entry.Filename, value)
					if err != nil {
						return nil, err
					}
					resolved[entry.Target] = path
					redactValues = append(redactValues, string(value))
				} else {
					value, err := manager.Get(selected, entryName)
					if err != nil {
						return nil, fmt.Errorf("secret resolution failed: environment key %q is unavailable", entryName)
					}
					resolved[entry.Target] = value
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
		Cleanup: cleanup, AllowShell: opts.AllowShell,
	})
}

// RunWorkspace executes arbitrary argv only after the caller has authorized a
// trusted workspace session. It deliberately uses the same encrypted
// environment resolution, temporary file workspace, redaction, CI protection,
// and audit path as strict policy commands. Authorization and environment
// pinning remain the caller's responsibility.
func RunWorkspace(ctx context.Context, root, environment string, argv []string, opts Options) (*runner.Result, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("workspace execution requires argv")
	}
	if environment == "" {
		return nil, fmt.Errorf("workspace execution requires a pinned environment")
	}
	manager, err := openEnvironment(root)
	if err != nil {
		return nil, fmt.Errorf("environment store unavailable: %w", err)
	}
	set, ok := manager.Set(environment)
	if !ok || manager.Expired(set) {
		return nil, fmt.Errorf("environment %q is unavailable", environment)
	}
	names := make([]string, 0, len(set.Entries))
	for _, entry := range set.Entries {
		names = append(names, entry.Name)
	}
	// The transient file is never written to disk. Version two directs Run to
	// resolve each entry from the encrypted local environment store.
	f := &policy.File{
		Version:  policy.SupportedVersionV2,
		Provider: "passthrough",
		Commands: []policy.Command{{ID: "workspace", Argv: append([]string(nil), argv...), Secrets: names}},
	}
	opts.Environment = environment
	opts.AllowShell = true
	res, err := Run(ctx, f, "", root, "workspace", opts)
	if err != nil {
		return nil, err
	}
	return res, nil
}
