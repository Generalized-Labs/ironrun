// Package execution is the shared sealed-run path for CLI, MCP, and local API
// callers. Authorization remains the caller's responsibility; secret
// resolution, injection, redaction, sandbox controls, and audit are centralized.
package execution

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
	"github.com/generalized-labs/ironrun/internal/provider"
	"github.com/generalized-labs/ironrun/internal/runner"
	"github.com/generalized-labs/ironrun/internal/scrub"
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
	// DisableSeccomp disables the Linux seccomp syscall filter for this run.
	// Operator flag only (--disable-seccomp on `ironrun run`); the legacy
	// IRONRUN_SECCOMP=off environment kill-switch is deliberately NOT honored.
	// Its use is logged loudly to stderr.
	DisableSeccomp bool
	// DisableEntropyScan skips the post-run high-entropy output scan.
	// Operator flag only (--disable-entropy-scan); the legacy
	// IRONRUN_ENTROPY_SCAN=off environment variable is ignored.
	DisableEntropyScan bool
	// AllowPullRequestTarget permits secret exposure on GitHub
	// pull_request_target CI events. Operator flag only
	// (--allow-pull-request-target); the legacy IRONRUN_ALLOW_PRT=1
	// environment variable is ignored.
	AllowPullRequestTarget bool
	// NoSeal disables the sealed-child hardening (RLIMIT_CORE=0, anti-core-dump).
	// Operator flag only (--no-seal); any inherited IRONRUN_NO_SEAL
	// environment value is stripped and ignored.
	NoSeal bool
	// EmitGitHubMasks prints ::add-mask:: workflow commands for every managed
	// secret value after resolution. Operator flag only (--emit-github-masks
	// on `ironrun run`); the GITHUB_ACTIONS environment variable is
	// deliberately NOT consulted — the environment is agent-reachable, so an
	// env-gated switch would let a contained agent exfiltrate every secret to
	// stdout with a single variable. Only pass this flag when the operator
	// knows the run is inside GitHub Actions.
	EmitGitHubMasks bool
	// AllowWorkspaceNetwork opts the transient trusted-workspace policy out of
	// network isolation (policy-level allow_network on the synthetic
	// "workspace" command). Used by tests and hosts where unprivileged network
	// namespaces are unavailable; policy strict mode never sets it.
	AllowWorkspaceNetwork bool
}

// resolveSeccomp reports whether the seccomp filter should be requested for
// this run. The operator controls this via policy (per-command `seccomp` /
// `seccomp_default`) or the --disable-seccomp CLI flag. The legacy
// IRONRUN_SECCOMP=off environment kill-switch is deliberately NOT honored: a
// contained agent inherits the environment, so an env-gated security switch is
// agent-reachable. When the flag is used, we log loudly that a security
// control is being weakened.
func resolveSeccomp(f *policy.File, cmd *policy.Command, disableSeccomp bool) bool {
	if os.Getenv("IRONRUN_SECCOMP") != "" {
		fmt.Fprintln(os.Stderr, "[ironrun] SECURITY WARNING: IRONRUN_SECCOMP is set but no longer honored; use the --disable-seccomp operator flag instead")
	}
	if disableSeccomp {
		fmt.Fprintln(os.Stderr, "[ironrun] SECURITY WARNING: --disable-seccomp: the Linux seccomp syscall filter will NOT be installed for this run")
		return false
	}
	return cmd.SeccompEnabled(f)
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
	seccompOn := resolveSeccomp(f, pCmd, opts.DisableSeccomp)
	var cleanup func() error
	if files != nil {
		cleanup = files.Close
	}
	if opts.EmitGitHubMasks {
		emitGitHubMasks(resolved, redactValues)
	}
	return runner.Run(ctx, pCmd, runner.Options{
		Stdout: opts.Stdout, Stderr: opts.Stderr, WorkDir: root,
		Secrets: resolved, RedactValues: redactValues, AuditSecrets: auditSecrets, Seccomp: &seccompOn, Audit: opts.Audit, SessionID: opts.SessionID,
		Cleanup: cleanup, AllowShell: opts.AllowShell,
		DisableEntropyScan: opts.DisableEntropyScan, AllowPullRequestTarget: opts.AllowPullRequestTarget,
		NoSeal: opts.NoSeal,
	})
}

// emitGitHubMasks prints a ::add-mask:: workflow command for every managed
// secret value (environment values in resolved plus file-secret contents in
// extra) and its encoded variants (base64, base64-url, percent-encoding — see
// scrub.Variants). GitHub masks each registered string in all subsequent log
// output, which covers leak paths the streamed redactor never sees
// (environment dumps, set -x traces from later steps).
//
// The caller gates this on Options.EmitGitHubMasks, an explicit operator
// flag (--emit-github-masks). The GITHUB_ACTIONS environment variable is
// deliberately not consulted: the environment is agent-reachable, so an
// env-gated switch would let a contained agent dump every secret value to
// stdout by setting one variable.
//
// Values shorter than scrub.MinSecretLen are skipped — a tiny needle would
// mask half the log in false positives.
func emitGitHubMasks(resolved map[string]string, extra []string) {
	values := make([]string, 0, len(resolved)+len(extra))
	seen := make(map[string]bool, len(resolved)+len(extra))
	for _, v := range resolved {
		if len(v) < scrub.MinSecretLen || seen[v] {
			continue
		}
		seen[v] = true
		values = append(values, v)
	}
	for _, v := range extra {
		if len(v) < scrub.MinSecretLen || seen[v] {
			continue
		}
		seen[v] = true
		values = append(values, v)
	}
	sort.Strings(values)
	for _, v := range values {
		for _, variant := range scrub.Variants(v) {
			fmt.Printf("::add-mask::%s\n", variant)
		}
	}
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
		Commands: []policy.Command{{ID: "workspace", Argv: append([]string(nil), argv...), Secrets: names, AllowNetwork: opts.AllowWorkspaceNetwork}},
	}
	opts.Environment = environment
	opts.AllowShell = true
	res, err := Run(ctx, f, "", root, "workspace", opts)
	if err != nil {
		return nil, err
	}
	return res, nil
}
