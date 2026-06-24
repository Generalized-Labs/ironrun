// Package pending stores agent-proposed commands awaiting human approval.
//
// Proposals live in a SEPARATE file (.ironrun/pending.yml next to the policy),
// not in ironrun.yml — both because the policy parser rejects unknown top-level
// keys, and because the security boundary must be unmistakable: the MCP server
// may append here, but only ironrun.yml is ever executed. Nothing in this store
// is reachable by run_sealed until a human runs `ironrun approve`.
package pending

import (
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Proposal is a command an agent proposed via propose_command. It is NEVER
// runnable directly; only `ironrun approve` can promote it into the policy.
type Proposal struct {
	ID         string            `yaml:"id"`
	Argv       []string          `yaml:"argv"`
	Env        map[string]string `yaml:"env,omitempty"`
	Reason     string            `yaml:"reason,omitempty"`
	ProposedAt string            `yaml:"proposed_at"`
	Status     string            `yaml:"status"` // always "pending" on disk
}

// Store is the on-disk pending file.
type Store struct {
	Proposals []Proposal `yaml:"proposals"`
}

// Path returns the pending-store path for a policy path:
// <dir(policyPath)>/.ironrun/pending.yml
func Path(policyPath string) string {
	return filepath.Join(filepath.Dir(policyPath), ".ironrun", "pending.yml")
}

// Load reads the store. A missing file yields an empty store, not an error.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{}, nil
		}
		return nil, err
	}
	var s Store
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes the store, creating .ironrun (0700) and the file (0600).
func Save(path string, s *Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Find returns the proposal with the given id, or nil.
func (s *Store) Find(id string) *Proposal {
	for i := range s.Proposals {
		if s.Proposals[i].ID == id {
			return &s.Proposals[i]
		}
	}
	return nil
}

// Upsert adds the proposal, or replaces an existing one with the same id (so a
// re-proposal updates in place instead of duplicating).
func (s *Store) Upsert(p Proposal) {
	for i := range s.Proposals {
		if s.Proposals[i].ID == p.ID {
			s.Proposals[i] = p
			return
		}
	}
	s.Proposals = append(s.Proposals, p)
	sort.Slice(s.Proposals, func(i, j int) bool { return s.Proposals[i].ID < s.Proposals[j].ID })
}

// Remove deletes the proposal with id, returning it and whether it existed.
func (s *Store) Remove(id string) (Proposal, bool) {
	for i := range s.Proposals {
		if s.Proposals[i].ID == id {
			p := s.Proposals[i]
			s.Proposals = append(s.Proposals[:i], s.Proposals[i+1:]...)
			return p, true
		}
	}
	return Proposal{}, false
}
