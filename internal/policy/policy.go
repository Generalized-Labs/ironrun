// Package policy loads and validates ironrun policy files (ironrun.yml).
package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the top-level policy document.
type File struct {
	Version  string    `yaml:"version"`
	Provider string    `yaml:"provider"` // "1password" | "env" | "doppler"
	Commands []Command `yaml:"commands"`
	// EnvironmentSet opts commands into the CLI-managed project environment
	// store. Empty preserves the legacy provider-only resolution path.
	EnvironmentSet string `yaml:"environment_set"`
	// Secrets declares onboarding aliases. Values are stored outside the policy
	// file and are resolved only for commands that explicitly bind them.
	Secrets map[string]Secret `yaml:"secrets"`

	// SeccompDefault sets the policy-wide default for the per-command seccomp
	// syscall filter (Linux). nil means "on". A command's own Seccomp overrides it.
	SeccompDefault *bool `yaml:"seccomp_default"`
	// AuditLog overrides the audit log path ("off" disables auditing). When empty,
	// the IRONRUN_AUDIT_LOG env var or the per-user default location is used.
	AuditLog string `yaml:"audit_log"`
	// AllowProposals lets agents stage NEW commands (via the propose_command MCP
	// tool) for the user to approve. Off by default. The run path NEVER executes
	// a proposed command — only `ironrun approve` promotes it into Commands.
	AllowProposals bool `yaml:"allow_proposals"`
	// RequireAgentLeases makes MCP execution fail closed unless the current MCP
	// server session has a human-approved, unexpired lease for the selected
	// environment and command. CLI execution remains the human authority path.
	RequireAgentLeases bool `yaml:"require_agent_leases"`
}

// Secret binds a user-facing alias to the environment variable a child needs.
// The value itself is never part of the policy document.
type Secret struct {
	Env      string   `yaml:"env"`
	Store    string   `yaml:"store"`
	Allow    []string `yaml:"allow"`
	Kind     string   `yaml:"kind,omitempty"`     // env (default) | file
	Filename string   `yaml:"filename,omitempty"` // safe basename for file secrets
}

func (s Secret) EffectiveKind() string {
	if s.Kind == "" {
		return "env"
	}
	return s.Kind
}

// Command defines one allowed invocation and the secrets it needs.
type Command struct {
	ID        string            `yaml:"id"`
	Argv      []string          `yaml:"argv"`       // exact binary + args
	Env       map[string]string `yaml:"env"`        // envvar -> secret ref
	Secrets   []string          `yaml:"secrets"`    // onboarding aliases declared in File.Secrets
	TTL       Duration          `yaml:"ttl"`        // max wall-clock duration
	MaxBytes  int64             `yaml:"max_bytes"`  // cap on total output bytes (0=unlimited)
	NoNetwork bool              `yaml:"no_network"` // block child network (best-effort)
	WorkDir   string            `yaml:"workdir"`    // optional working directory
	// Seccomp toggles the Linux seccomp syscall filter for this command. nil
	// means "use the policy default" (which itself defaults to on). Set false to
	// opt a command out — e.g. a debugger/strace that legitimately needs ptrace.
	Seccomp *bool `yaml:"seccomp"`
}

// SeccompEnabled resolves whether the seccomp filter applies to this command:
// the command's own setting wins, then the policy default, then on.
func (c *Command) SeccompEnabled(f *File) bool {
	if c.Seccomp != nil {
		return *c.Seccomp
	}
	if f != nil && f.SeccompDefault != nil {
		return *f.SeccompDefault
	}
	return true
}

// Duration is a yaml-decodable time.Duration.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Value == "" {
		d.Duration = 0
		return nil
	}
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("policy: bad duration %q: %w", value.Value, err)
	}
	d.Duration = dur
	return nil
}

var (
	ErrNotFound   = errors.New("policy file not found")
	ErrMalformed  = errors.New("policy file malformed")
	ErrBadVersion = errors.New("policy: unsupported version")
	ErrNoCommands = errors.New("policy: no commands defined")
)

const SupportedVersion = "1"

// Load reads and validates a policy file from path.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, path, err)
	}
	return Parse(data)
}

// Parse validates a policy from raw YAML bytes.
func Parse(data []byte) (*File, error) {
	var f File
	br := bytesReader(data)
	dec := yaml.NewDecoder(&br)
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	if f.Version != SupportedVersion {
		return nil, fmt.Errorf("%w: got %q want %q", ErrBadVersion, f.Version, SupportedVersion)
	}
	if len(f.Commands) == 0 {
		return nil, ErrNoCommands
	}
	fileTargets := map[string]string{}
	fileNames := map[string]string{}
	for alias, secret := range f.Secrets {
		if secret.EffectiveKind() != "env" && secret.EffectiveKind() != "file" {
			return nil, fmt.Errorf("%w: secret %q has unsupported kind %q", ErrMalformed, alias, secret.Kind)
		}
		if !validEnvTarget(secret.Env) {
			return nil, fmt.Errorf("%w: secret %q has invalid environment target %q", ErrMalformed, alias, secret.Env)
		}
		if secret.EffectiveKind() == "file" {
			if secret.Filename == "" || filepath.Base(secret.Filename) != secret.Filename || secret.Filename == "." || secret.Filename == ".." || strings.ContainsAny(secret.Filename, `/\\`) {
				return nil, fmt.Errorf("%w: secret %q file name must be a safe basename", ErrMalformed, alias)
			}
			if previous, exists := fileTargets[secret.Env]; exists {
				return nil, fmt.Errorf("%w: file secrets %q and %q share target %q", ErrMalformed, previous, alias, secret.Env)
			}
			fileTargets[secret.Env] = alias
			if previous, exists := fileNames[secret.Filename]; exists {
				return nil, fmt.Errorf("%w: file secrets %q and %q share filename %q", ErrMalformed, previous, alias, secret.Filename)
			}
			fileNames[secret.Filename] = alias
		}
	}

	seen := map[string]bool{}
	for i, cmd := range f.Commands {
		if cmd.ID == "" {
			return nil, fmt.Errorf("%w: command[%d] missing id", ErrMalformed, i)
		}
		if seen[cmd.ID] {
			return nil, fmt.Errorf("%w: duplicate command id %q", ErrMalformed, cmd.ID)
		}
		seen[cmd.ID] = true
		if len(cmd.Argv) == 0 {
			return nil, fmt.Errorf("%w: command %q missing argv", ErrMalformed, cmd.ID)
		}
		for _, alias := range cmd.Secrets {
			secret, ok := f.Secrets[alias]
			if !ok || secret.Env == "" {
				return nil, fmt.Errorf("%w: command %q references undeclared secret %q", ErrMalformed, cmd.ID, alias)
			}
			allowed := false
			for _, id := range secret.Allow {
				if id == cmd.ID {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, fmt.Errorf("%w: secret %q is not allowed for command %q", ErrMalformed, alias, cmd.ID)
			}
		}
	}
	return &f, nil
}

func validEnvTarget(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Lookup returns the command with the given id, or an error.
func (f *File) Lookup(id string) (*Command, error) {
	for i := range f.Commands {
		if f.Commands[i].ID == id {
			return &f.Commands[i], nil
		}
	}
	return nil, fmt.Errorf("command %q not found in policy", id)
}

// AuthorizeArgv checks that the supplied argv exactly matches the policy.
// This prevents argv injection (e.g. shell glob expansion, extra flags).
func AuthorizeArgv(cmd *Command, argv []string) error {
	if len(argv) != len(cmd.Argv) {
		return fmt.Errorf("argv mismatch: got %d args want %d", len(argv), len(cmd.Argv))
	}
	for i := range argv {
		if argv[i] != cmd.Argv[i] {
			return fmt.Errorf("argv[%d] mismatch: got %q want %q", i, argv[i], cmd.Argv[i])
		}
	}
	return nil
}

// IsShellString returns true if the first element of argv looks like a shell
// invocation (sh, bash, zsh, etc). Shell execution is always denied unless the
// policy argv itself starts with a shell — but we warn callers regardless.
func IsShellString(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "sh", "bash", "zsh", "fish", "dash", "ash", "ksh", "csh", "tcsh", "rbash",
		"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ash", "/bin/ksh", "/bin/csh", "/bin/tcsh",
		"/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish", "/usr/bin/dash", "/usr/bin/ksh",
		"/usr/local/bin/bash", "/usr/local/bin/zsh", "/usr/local/bin/fish":
		return true
	}
	return false
}

// SetDuration sets the Duration from a string — useful in tests.
func (d *Duration) SetDuration(s string) error {
	if s == "" {
		d.Duration = 0
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

type bytesReader []byte

func (b *bytesReader) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}
