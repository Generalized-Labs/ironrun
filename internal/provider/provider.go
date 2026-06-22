// Package provider resolves secret references to their values.
// Providers are pluggable: 1password, vault, doppler, infisical, env, passthrough.
package provider

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Provider resolves a secret reference (e.g. "op://vault/item/field") to its
// plaintext value. Implementations must be safe for concurrent use.
type Provider interface {
	// Resolve returns the plaintext value for the given reference.
	Resolve(ref string) (string, error)
	// Name returns the provider identifier.
	Name() string
}

// HealthChecker is an optional interface a Provider may implement so that
// `ironrun doctor` can verify the provider is installed and authenticated.
// Providers that need no external CLI (env, envfile, passthrough) do not
// implement it and are treated as always ready.
type HealthChecker interface {
	// Check returns nil if the provider is ready to resolve secrets, or an
	// error describing what is wrong (CLI missing, not authenticated).
	Check() error
}

var (
	ErrNotConfigured    = errors.New("provider not configured")
	ErrResolve          = errors.New("provider: resolve failed")
	ErrOpMissing        = errors.New("1password: op CLI not found in PATH")
	ErrOpAuth           = errors.New("1password: not authenticated (run: op signin)")
	ErrDopplerMissing   = errors.New("doppler: doppler CLI not found in PATH")
	ErrInfisicalMissing = errors.New("infisical: infisical CLI not found in PATH")
	ErrVaultMissing     = errors.New("vault: vault CLI not found in PATH")
	ErrVaultAuth        = errors.New("vault: not authenticated (set VAULT_ADDR and VAULT_TOKEN, or run: vault login)")
)

// Indirection points over os/exec so tests can stub the CLI layer.
var (
	lookPath    = exec.LookPath
	execCommand = exec.Command
)

// New returns a Provider for the given name.
// Supported: "1password", "vault", "doppler", "infisical", "env", "envfile", "passthrough"
// For envfile, pass the path as: "envfile:/path/to/.secrets"
func New(name string) (Provider, error) {
	nameLower := strings.ToLower(name)

	// Handle envfile:/path/to/file syntax
	if after, ok := strings.CutPrefix(nameLower, "envfile:"); ok {
		return newEnvFileProvider(after)
	}

	switch nameLower {
	case "1password", "op":
		return &onePasswordProvider{}, nil
	case "vault", "hashicorp":
		return &vaultProvider{}, nil
	case "doppler":
		return &dopplerProvider{}, nil
	case "infisical":
		return &infisicalProvider{}, nil
	case "env", "environment":
		return &envProvider{}, nil
	case "passthrough", "":
		return &passthroughProvider{}, nil
	default:
		return nil, fmt.Errorf("%w: unknown provider %q (supported: 1password, vault, doppler, infisical, env, envfile:/path, passthrough)", ErrNotConfigured, name)
	}
}

// ResolveAll resolves all env-var mappings in a command's Env map.
// Returns a map of envvar -> resolved plaintext value.
func ResolveAll(p Provider, refs map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	for envVar, ref := range refs {
		val, err := p.Resolve(ref)
		if err != nil {
			return nil, fmt.Errorf("resolving %q → %q: %w", envVar, ref, err)
		}
		out[envVar] = val
	}
	return out, nil
}

// --- 1Password provider ---

type onePasswordProvider struct{}

func (o *onePasswordProvider) Name() string { return "1password" }

func (o *onePasswordProvider) Check() error {
	if _, err := lookPath("op"); err != nil {
		return ErrOpMissing
	}
	if err := execCommand("op", "whoami").Run(); err != nil {
		return ErrOpAuth
	}
	return nil
}

func (o *onePasswordProvider) Resolve(ref string) (string, error) {
	opBin, err := lookPath("op")
	if err != nil {
		return "", ErrOpMissing
	}

	// ref format: "op://vault/item/field" or plain item name
	// We use: op read --no-newline <ref>
	cmd := execCommand(opBin, "read", "--no-newline", ref)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "not signed in") || strings.Contains(stderr, "sign in") {
				return "", ErrOpAuth
			}
			return "", fmt.Errorf("%w: op read %q: %s", ErrResolve, ref, strings.TrimSpace(stderr))
		}
		return "", fmt.Errorf("%w: op read %q: %v", ErrResolve, ref, err)
	}
	return string(out), nil
}

// --- HashiCorp Vault provider ---
// Resolves refs of the form "vault://<path>#<field>" against a KV v2 mount using
// the vault CLI. The "vault://" prefix is optional. The vault CLI reads VAULT_ADDR
// and VAULT_TOKEN from the environment (or ~/.vault-token), so no extra config is
// needed here.
//
// Example policy:
//   provider: vault
//   commands:
//     - id: deploy
//       argv: [./deploy.sh]
//       env:
//         DATABASE_URL: vault://secret/myapp#DATABASE_URL
//         API_KEY:      secret/myapp#API_KEY   # vault:// prefix optional

type vaultProvider struct{}

func (v *vaultProvider) Name() string { return "vault" }

func (v *vaultProvider) Check() error {
	if _, err := lookPath("vault"); err != nil {
		return ErrVaultMissing
	}
	if err := execCommand("vault", "token", "lookup").Run(); err != nil {
		return ErrVaultAuth
	}
	return nil
}

func (v *vaultProvider) Resolve(ref string) (string, error) {
	path, field, ok := strings.Cut(strings.TrimPrefix(ref, "vault://"), "#")
	if !ok || path == "" || field == "" {
		return "", fmt.Errorf("%w: vault ref %q must be vault://<path>#<field> (e.g. vault://secret/myapp#API_KEY)", ErrResolve, ref)
	}

	vaultBin, err := lookPath("vault")
	if err != nil {
		return "", ErrVaultMissing
	}

	// vault kv get -field=FIELD PATH  (KV v2)
	cmd := execCommand(vaultBin, "kv", "get", "-field="+field, path)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			low := strings.ToLower(stderr)
			if strings.Contains(low, "missing client token") ||
				strings.Contains(low, "permission denied") ||
				strings.Contains(low, "403") {
				return "", ErrVaultAuth
			}
			return "", fmt.Errorf("%w: vault kv get %q: %s", ErrResolve, path, stderr)
		}
		return "", fmt.Errorf("%w: vault kv get %q: %v", ErrResolve, path, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// --- Doppler provider ---
// Resolves refs of the form "doppler://PROJECT/CONFIG/SECRET_NAME" or just "SECRET_NAME"
// using the doppler CLI. The doppler CLI must be installed and authenticated.
//
// Example policy:
//   provider: doppler
//   commands:
//     - id: deploy
//       argv: [./deploy.sh]
//       env:
//         DATABASE_URL: doppler://myapp/production/DATABASE_URL
//         API_KEY: API_KEY   # shorthand — resolves from currently-configured project/config

type dopplerProvider struct{}

func (d *dopplerProvider) Name() string { return "doppler" }

func (d *dopplerProvider) Check() error {
	if _, err := lookPath("doppler"); err != nil {
		return ErrDopplerMissing
	}
	if err := execCommand("doppler", "me").Run(); err != nil {
		return errors.New("doppler: not authenticated (run: doppler login)")
	}
	return nil
}

func (d *dopplerProvider) Resolve(ref string) (string, error) {
	dopplerBin, err := lookPath("doppler")
	if err != nil {
		return "", ErrDopplerMissing
	}

	// Parse "doppler://project/config/secret" or plain "SECRET_NAME"
	var args []string
	if after, ok := strings.CutPrefix(ref, "doppler://"); ok {
		parts := strings.SplitN(after, "/", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("%w: doppler ref %q must be doppler://project/config/SECRET", ErrResolve, ref)
		}
		// doppler secrets get SECRET_NAME --project PROJECT --config CONFIG --plain
		args = []string{"secrets", "get", parts[2],
			"--project", parts[0],
			"--config", parts[1],
			"--plain", "--no-read-env"}
	} else {
		// Use currently-configured project/config from doppler.yaml or env
		args = []string{"secrets", "get", ref, "--plain", "--no-read-env"}
	}

	cmd := execCommand(dopplerBin, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			return "", fmt.Errorf("%w: doppler get %q: %s", ErrResolve, ref, stderr)
		}
		return "", fmt.Errorf("%w: doppler get %q: %v", ErrResolve, ref, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// --- Infisical provider ---
// Resolves refs using the infisical CLI.
// Ref format: "infisical://PROJECT_ID/ENV/SECRET_NAME" or just "SECRET_NAME"
//
// Example policy:
//   provider: infisical
//   commands:
//     - id: deploy
//       argv: [./deploy.sh]
//       env:
//         DATABASE_URL: infisical://abc123/prod/DATABASE_URL
//         API_KEY: API_KEY   # shorthand, uses currently-logged-in project

type infisicalProvider struct{}

func (i *infisicalProvider) Name() string { return "infisical" }

func (i *infisicalProvider) Check() error {
	if _, err := lookPath("infisical"); err != nil {
		return ErrInfisicalMissing
	}
	// Infisical auth is token/login-dependent and varies by setup; the reliable
	// signal here is that the CLI is installed. Auth is verified at resolve time.
	return nil
}

func (i *infisicalProvider) Resolve(ref string) (string, error) {
	infisicalBin, err := lookPath("infisical")
	if err != nil {
		return "", ErrInfisicalMissing
	}

	// Parse "infisical://projectId/env/SECRET_NAME"
	var args []string
	if after, ok := strings.CutPrefix(ref, "infisical://"); ok {
		parts := strings.SplitN(after, "/", 3)
		if len(parts) != 3 {
			return "", fmt.Errorf("%w: infisical ref %q must be infisical://projectId/env/SECRET_NAME", ErrResolve, ref)
		}
		// infisical secrets get SECRET_NAME --projectId ID --env ENV --plain
		args = []string{"secrets", "get", parts[2],
			"--projectId", parts[0],
			"--env", parts[1],
			"--plain", "--silent"}
	} else {
		// Use currently-configured project/env
		args = []string{"secrets", "get", ref, "--plain", "--silent"}
	}

	cmd := execCommand(infisicalBin, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			return "", fmt.Errorf("%w: infisical get %q: %s", ErrResolve, ref, stderr)
		}
		return "", fmt.Errorf("%w: infisical get %q: %v", ErrResolve, ref, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// --- Env provider ---
// Resolves refs that are plain environment variable names, or KEY=VALUE literals.

type envProvider struct{}

func (e *envProvider) Name() string { return "env" }

func (e *envProvider) Resolve(ref string) (string, error) {
	// Support literal values prefixed with "literal:"
	if after, ok := strings.CutPrefix(ref, "literal:"); ok {
		return after, nil
	}
	// Support env:VARNAME syntax
	if after, ok := strings.CutPrefix(ref, "env:"); ok {
		ref = after
	}
	val, ok := os.LookupEnv(ref)
	if !ok {
		return "", fmt.Errorf("%w: env var %q not set", ErrResolve, ref)
	}
	return val, nil
}

// --- Passthrough provider ---
// Returns the ref value as-is. Useful for testing and for literal values.

type passthroughProvider struct{}

func (p *passthroughProvider) Name() string { return "passthrough" }

func (p *passthroughProvider) Resolve(ref string) (string, error) {
	return ref, nil
}

// --- EnvFile provider ---
// Reads secrets from a file in KEY=VALUE format (like .env files).
// The file is read at provider creation time, not at resolve time.
// This allows secrets to be stored outside the shell environment that
// AI agents can access via printenv/echo.
//
// Example policy:
//   provider: "envfile:~/.secrets/myproject.env"
//   commands:
//     - id: test
//       env:
//         API_KEY: API_KEY   # reads from the file, not shell env
//
// File format:
//   API_KEY=***
//   DATABASE_URL=postgres://...
//   # comments are ignored
//   MULTILINE="line1\nline2"  # \n is expanded

type envFileProvider struct {
	secrets map[string]string
	path    string
}

func newEnvFileProvider(path string) (*envFileProvider, error) {
	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("%w: cannot expand ~: %v", ErrResolve, err)
		}
		path = home + path[1:]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read secrets file %q: %v", ErrResolve, path, err)
	}

	secrets := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Remove surrounding quotes if present
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		// Expand \n to actual newlines
		value = strings.ReplaceAll(value, "\\n", "\n")
		secrets[key] = value
	}

	return &envFileProvider{secrets: secrets, path: path}, nil
}

func (e *envFileProvider) Name() string { return "envfile" }

func (e *envFileProvider) Resolve(ref string) (string, error) {
	// Support envfile:VARNAME syntax (strip prefix if present)
	if after, ok := strings.CutPrefix(ref, "envfile:"); ok {
		ref = after
	}
	val, ok := e.secrets[ref]
	if !ok {
		return "", fmt.Errorf("%w: secret %q not found in %s", ErrResolve, ref, e.path)
	}
	return val, nil
}
