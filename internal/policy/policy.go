// Package policy loads and validates ironrun policy files (ironrun.yml).
package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the top-level policy document.
type File struct {
	Version  string    `yaml:"version"`
	Provider string    `yaml:"provider"` // "1password" | "env" | "doppler"
	Commands []Command `yaml:"commands"`
	// AllowProposals lets agents stage NEW commands (via the propose_command MCP
	// tool) for the user to approve. Off by default. The run path NEVER executes
	// a proposed command — only `ironrun approve` promotes it into Commands.
	AllowProposals bool `yaml:"allow_proposals"`
}

// Command defines one allowed invocation and the secrets it needs.
type Command struct {
	ID        string            `yaml:"id"`
	Argv      []string          `yaml:"argv"`       // exact binary + args
	Env       map[string]string `yaml:"env"`        // envvar -> secret ref
	TTL       Duration          `yaml:"ttl"`        // max wall-clock duration
	MaxBytes  int64             `yaml:"max_bytes"`  // cap on total output bytes (0=unlimited)
	NoNetwork bool              `yaml:"no_network"` // block child network (best-effort)
	WorkDir   string            `yaml:"workdir"`    // optional working directory
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
	}
	return &f, nil
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
