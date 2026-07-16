// Package access persists human-reviewed agent requests and revocable command
// leases. It never stores secret values.
package access

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	stateVersion        = 2
	DefaultRequestTTL   = 15 * time.Minute
	DefaultLeaseTTL     = time.Hour
	DefaultWorkspaceTTL = 2 * time.Hour
	MaxLeaseTTL         = 24 * time.Hour
	maxPendingSession   = 32
)

type RequestKind string
type RequestStatus string

const (
	RequestSecret    RequestKind = "secret"
	RequestLease     RequestKind = "lease"
	RequestWorkspace RequestKind = "workspace"

	StatusPending   RequestStatus = "pending"
	StatusFulfilled RequestStatus = "fulfilled"
	StatusApproved  RequestStatus = "approved"
	StatusDenied    RequestStatus = "denied"
	StatusExpired   RequestStatus = "expired"
)

var (
	ErrNotFound     = errors.New("access record not found")
	ErrNotPending   = errors.New("access request is not pending")
	ErrUnauthorized = errors.New("agent lease required")
)

type Request struct {
	ID          string        `json:"id"`
	Kind        RequestKind   `json:"kind"`
	Status      RequestStatus `json:"status"`
	SessionID   string        `json:"session_id"`
	Environment string        `json:"environment"`
	SecretAlias string        `json:"secret_alias,omitempty"`
	SecretKey   string        `json:"secret_key,omitempty"`
	Commands    []string      `json:"commands,omitempty"`
	// FirstArgv is only safe command metadata shown while a human decides
	// whether to trust a workspace session. It is never interpreted as policy.
	FirstArgv        []string      `json:"first_argv,omitempty"`
	Reason           string        `json:"reason"`
	RequestedTTL     time.Duration `json:"requested_ttl,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
	ExpiresAt        time.Time     `json:"expires_at"`
	ResolvedAt       *time.Time    `json:"resolved_at,omitempty"`
	ResultingLeaseID string        `json:"resulting_lease_id,omitempty"`
}

// WorkspaceGrant is a deliberately broad, human-approved capability for one
// MCP server session in one project environment. It does not hold secret
// values: the execution layer reads them directly from the encrypted vault.
type WorkspaceGrant struct {
	ID          string     `json:"id"`
	RequestID   string     `json:"request_id"`
	SessionID   string     `json:"session_id"`
	ProjectRoot string     `json:"project_root"`
	Environment string     `json:"environment"`
	Network     string     `json:"network"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	PausedAt    *time.Time `json:"paused_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type Lease struct {
	ID          string     `json:"id"`
	RequestID   string     `json:"request_id"`
	SessionID   string     `json:"session_id"`
	Environment string     `json:"environment"`
	Commands    []string   `json:"commands"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type state struct {
	Version         int              `json:"version"`
	Requests        []Request        `json:"requests"`
	Leases          []Lease          `json:"leases"`
	WorkspaceGrants []WorkspaceGrant `json:"workspace_grants,omitempty"`
}

type Manager struct {
	path string
	root string
	now  func() time.Time
}

func Open(root string) (*Manager, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, ".ironrun")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{path: filepath.Join(dir, "access.json"), root: root, now: time.Now}
	if _, err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

// CreateWorkspaceRequest deduplicates a request for a broad but temporary
// workspace capability. The project root is persisted only to make the scope
// inspectable; access state remains physically project-local.
func (m *Manager) CreateWorkspaceRequest(sessionID, environment string, firstArgv []string, ttl time.Duration, reason string) (Request, error) {
	if err := validateIdentity(sessionID, environment); err != nil {
		return Request{}, err
	}
	if len(firstArgv) == 0 || strings.TrimSpace(firstArgv[0]) == "" {
		return Request{}, errors.New("workspace request requires argv")
	}
	if ttl <= 0 {
		ttl = DefaultWorkspaceTTL
	}
	if ttl > MaxLeaseTTL {
		return Request{}, fmt.Errorf("workspace ttl exceeds maximum %s", MaxLeaseTTL)
	}
	return m.createRequest(Request{
		Kind: RequestWorkspace, SessionID: sessionID, Environment: environment,
		FirstArgv: append([]string(nil), firstArgv...), RequestedTTL: ttl,
		Reason: cleanReason(reason),
	})
}

func (m *Manager) Path() string { return m.path }

func (m *Manager) CreateSecretRequest(sessionID, environment, alias, key, reason string) (Request, error) {
	return m.CreateSecretRequestForCommands(sessionID, environment, alias, key, nil, reason)
}

// CreateSecretRequestForCommands adds the exact sealed command context used by
// the unified review screen. Existing callers remain value-blind wrappers.
func (m *Manager) CreateSecretRequestForCommands(sessionID, environment, alias, key string, commands []string, reason string) (Request, error) {
	if err := validateIdentity(sessionID, environment); err != nil {
		return Request{}, err
	}
	if strings.TrimSpace(alias) == "" || strings.TrimSpace(key) == "" {
		return Request{}, errors.New("secret alias and key are required")
	}
	return m.createRequest(Request{
		Kind:        RequestSecret,
		SessionID:   sessionID,
		Environment: environment,
		SecretAlias: alias,
		SecretKey:   key,
		Commands:    canonicalCommands(commands),
		Reason:      cleanReason(reason),
	})
}

func (m *Manager) CreateLeaseRequest(sessionID, environment string, commands []string, ttl time.Duration, reason string) (Request, error) {
	if err := validateIdentity(sessionID, environment); err != nil {
		return Request{}, err
	}
	commands = canonicalCommands(commands)
	if len(commands) == 0 {
		return Request{}, errors.New("at least one command is required")
	}
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl > MaxLeaseTTL {
		ttl = MaxLeaseTTL
	}
	return m.createRequest(Request{
		Kind:         RequestLease,
		SessionID:    sessionID,
		Environment:  environment,
		Commands:     commands,
		Reason:       cleanReason(reason),
		RequestedTTL: ttl,
	})
}

func (m *Manager) createRequest(candidate Request) (Request, error) {
	var result Request
	err := m.mutate(func(st *state) error {
		now := m.now().UTC()
		expire(st, now)
		pending := 0
		for _, existing := range st.Requests {
			if existing.SessionID == candidate.SessionID && existing.Status == StatusPending {
				pending++
				if sameRequest(existing, candidate) {
					result = existing
					return nil
				}
			}
		}
		if pending >= maxPendingSession {
			return fmt.Errorf("too many pending requests for this session")
		}
		id, err := randomID("req")
		if err != nil {
			return err
		}
		candidate.ID = id
		candidate.Status = StatusPending
		candidate.CreatedAt = now
		candidate.ExpiresAt = now.Add(DefaultRequestTTL)
		st.Requests = append(st.Requests, candidate)
		result = candidate
		return nil
	})
	return result, err
}

func (m *Manager) Request(id string) (Request, error) {
	st, err := m.load()
	if err != nil {
		return Request{}, err
	}
	now := m.now().UTC()
	for _, request := range st.Requests {
		if request.ID == id {
			if request.Status == StatusPending && !now.Before(request.ExpiresAt) {
				request.Status = StatusExpired
			}
			return request, nil
		}
	}
	return Request{}, ErrNotFound
}

func (m *Manager) Requests() ([]Request, error) {
	if err := m.mutate(func(st *state) error {
		expire(st, m.now().UTC())
		return nil
	}); err != nil {
		return nil, err
	}
	st, err := m.load()
	if err != nil {
		return nil, err
	}
	out := append([]Request(nil), st.Requests...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) FulfillSecret(id string) (Request, error) {
	return m.FulfillSecretWith(id, nil)
}

// FulfillSecretWith runs the local storage commit while holding the same
// cross-process lock that transitions the request. This makes one-use capsule
// claims literal: concurrent claimers cannot both pass the pending check.
func (m *Manager) FulfillSecretWith(id string, commit func(Request) error) (Request, error) {
	var result Request
	err := m.resolveRequest(id, RequestSecret, StatusFulfilled, func(st *state, request *Request, now time.Time) error {
		result = *request
		if commit != nil {
			if err := commit(result); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		result.Status = StatusFulfilled
	}
	return result, err
}

func (m *Manager) ApproveLease(id string, ttl time.Duration) (Lease, error) {
	var lease Lease
	err := m.resolveRequest(id, RequestLease, StatusApproved, func(st *state, request *Request, now time.Time) error {
		if ttl <= 0 {
			ttl = request.RequestedTTL
		}
		if ttl <= 0 {
			ttl = DefaultLeaseTTL
		}
		if ttl > MaxLeaseTTL {
			return fmt.Errorf("lease ttl exceeds maximum %s", MaxLeaseTTL)
		}
		id, err := randomID("lease")
		if err != nil {
			return err
		}
		lease = Lease{
			ID:          id,
			RequestID:   request.ID,
			SessionID:   request.SessionID,
			Environment: request.Environment,
			Commands:    append([]string(nil), request.Commands...),
			CreatedAt:   now,
			ExpiresAt:   now.Add(ttl),
		}
		request.ResultingLeaseID = lease.ID
		st.Leases = append(st.Leases, lease)
		return nil
	})
	return lease, err
}

// ApproveWorkspace grants broad command execution only to the requesting MCP
// session and selected environment. A restarted MCP server has a fresh session
// ID, so old grants automatically stop authorizing it.
func (m *Manager) ApproveWorkspace(id string, ttl time.Duration) (WorkspaceGrant, error) {
	var grant WorkspaceGrant
	err := m.resolveRequest(id, RequestWorkspace, StatusApproved, func(st *state, request *Request, now time.Time) error {
		if ttl <= 0 {
			ttl = request.RequestedTTL
		}
		if ttl <= 0 {
			ttl = DefaultWorkspaceTTL
		}
		if ttl > MaxLeaseTTL {
			return fmt.Errorf("workspace ttl exceeds maximum %s", MaxLeaseTTL)
		}
		grantID, err := randomID("trust")
		if err != nil {
			return err
		}
		grant = WorkspaceGrant{
			ID: grantID, RequestID: request.ID, SessionID: request.SessionID,
			ProjectRoot: m.root, Environment: request.Environment, Network: "normal",
			CreatedAt: now, ExpiresAt: now.Add(ttl),
		}
		st.WorkspaceGrants = append(st.WorkspaceGrants, grant)
		request.ResultingLeaseID = grant.ID // compatibility field for request consumers.
		return nil
	})
	return grant, err
}

func (m *Manager) Deny(id string) error {
	return m.resolveRequest(id, "", StatusDenied, nil)
}

func (m *Manager) resolveRequest(id string, kind RequestKind, status RequestStatus, fn func(*state, *Request, time.Time) error) error {
	return m.mutate(func(st *state) error {
		now := m.now().UTC()
		expire(st, now)
		for i := range st.Requests {
			request := &st.Requests[i]
			if request.ID != id {
				continue
			}
			if request.Status != StatusPending {
				return fmt.Errorf("%w: %s", ErrNotPending, request.Status)
			}
			if kind != "" && request.Kind != kind {
				return fmt.Errorf("request %s is %s, not %s", id, request.Kind, kind)
			}
			if fn != nil {
				if err := fn(st, request, now); err != nil {
					return err
				}
			}
			request.Status = status
			request.ResolvedAt = &now
			return nil
		}
		return ErrNotFound
	})
}

func (m *Manager) Authorize(sessionID, environment, command string) error {
	st, err := m.load()
	if err != nil {
		return err
	}
	now := m.now().UTC()
	for _, lease := range st.Leases {
		if lease.SessionID != sessionID || lease.Environment != environment || lease.RevokedAt != nil || !now.Before(lease.ExpiresAt) {
			continue
		}
		if contains(lease.Commands, command) {
			return nil
		}
	}
	return ErrUnauthorized
}

func (m *Manager) Leases(sessionID string) ([]Lease, error) {
	st, err := m.load()
	if err != nil {
		return nil, err
	}
	out := make([]Lease, 0, len(st.Leases))
	for _, lease := range st.Leases {
		if sessionID == "" || lease.SessionID == sessionID {
			out = append(out, lease)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) Revoke(id, sessionID string) error {
	return m.mutate(func(st *state) error {
		now := m.now().UTC()
		for i := range st.Leases {
			lease := &st.Leases[i]
			if lease.ID != id {
				continue
			}
			if sessionID != "" && lease.SessionID != sessionID {
				return ErrUnauthorized
			}
			if lease.RevokedAt == nil {
				lease.RevokedAt = &now
			}
			return nil
		}
		return ErrNotFound
	})
}

// AuthorizeWorkspace returns the exact active grant, pinning the environment
// used by the caller through execution. Paused, expired, revoked, and
// cross-session grants all fail closed.
func (m *Manager) AuthorizeWorkspace(sessionID, environment string) (WorkspaceGrant, error) {
	st, err := m.load()
	if err != nil {
		return WorkspaceGrant{}, err
	}
	now := m.now().UTC()
	for _, grant := range st.WorkspaceGrants {
		if grant.SessionID == sessionID && grant.ProjectRoot == m.root && grant.Environment == environment && grant.PausedAt == nil && grant.RevokedAt == nil && now.Before(grant.ExpiresAt) {
			return grant, nil
		}
	}
	return WorkspaceGrant{}, ErrUnauthorized
}

func (m *Manager) WorkspaceGrants(sessionID string) ([]WorkspaceGrant, error) {
	st, err := m.load()
	if err != nil {
		return nil, err
	}
	out := make([]WorkspaceGrant, 0, len(st.WorkspaceGrants))
	for _, grant := range st.WorkspaceGrants {
		if sessionID == "" || grant.SessionID == sessionID {
			out = append(out, grant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Manager) PauseWorkspace(id string, paused bool) error {
	return m.mutate(func(st *state) error {
		now := m.now().UTC()
		for i := range st.WorkspaceGrants {
			grant := &st.WorkspaceGrants[i]
			if grant.ID != id {
				continue
			}
			if grant.RevokedAt != nil {
				return ErrUnauthorized
			}
			if paused {
				grant.PausedAt = &now
			} else {
				grant.PausedAt = nil
			}
			return nil
		}
		return ErrNotFound
	})
}

func (m *Manager) ExtendWorkspace(id string, ttl time.Duration) (WorkspaceGrant, error) {
	if ttl <= 0 || ttl > MaxLeaseTTL {
		return WorkspaceGrant{}, fmt.Errorf("workspace ttl must be between 1ns and %s", MaxLeaseTTL)
	}
	var result WorkspaceGrant
	err := m.mutate(func(st *state) error {
		now := m.now().UTC()
		for i := range st.WorkspaceGrants {
			grant := &st.WorkspaceGrants[i]
			if grant.ID != id {
				continue
			}
			if grant.RevokedAt != nil {
				return ErrUnauthorized
			}
			grant.ExpiresAt = now.Add(ttl)
			result = *grant
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (m *Manager) RevokeWorkspace(id string) error {
	return m.mutate(func(st *state) error {
		now := m.now().UTC()
		for i := range st.WorkspaceGrants {
			grant := &st.WorkspaceGrants[i]
			if grant.ID != id {
				continue
			}
			if grant.RevokedAt == nil {
				grant.RevokedAt = &now
			}
			return nil
		}
		return ErrNotFound
	})
}

func (m *Manager) load() (state, error) {
	st := state{Version: stateVersion, Requests: []Request{}, Leases: []Lease{}, WorkspaceGrants: []WorkspaceGrant{}}
	data, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return state{}, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return state{}, fmt.Errorf("parse access state: %w", err)
	}
	if st.Version != 1 && st.Version != stateVersion {
		return state{}, fmt.Errorf("unsupported access state version %d", st.Version)
	}
	if st.Version == 1 {
		st.Version = stateVersion
	}
	if st.WorkspaceGrants == nil {
		st.WorkspaceGrants = []WorkspaceGrant{}
	}
	return st, nil
}

func (m *Manager) mutate(fn func(*state) error) error {
	return withLock(m.path+".lock", func() error {
		st, err := m.load()
		if err != nil {
			return err
		}
		if err := fn(&st); err != nil {
			return err
		}
		return saveAtomic(m.path, st)
	})
}

func saveAtomic(path string, st state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".access-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return os.Chmod(path, 0600)
}

func withLock(path string, fn func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Mkdir(path, 0700)
		if err == nil {
			defer os.Remove(path) //nolint:errcheck
			return fn()
		}
		if !os.IsExist(err) {
			return err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for access-state lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func expire(st *state, now time.Time) {
	for i := range st.Requests {
		if st.Requests[i].Status == StatusPending && !now.Before(st.Requests[i].ExpiresAt) {
			st.Requests[i].Status = StatusExpired
			resolved := now
			st.Requests[i].ResolvedAt = &resolved
		}
	}
}

func sameRequest(a, b Request) bool {
	return a.Kind == b.Kind && a.Environment == b.Environment && a.SecretAlias == b.SecretAlias &&
		a.SecretKey == b.SecretKey && strings.Join(a.Commands, "\x00") == strings.Join(b.Commands, "\x00")
}

func canonicalCommands(commands []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command != "" && !seen[command] {
			seen[command] = true
			out = append(out, command)
		}
	}
	sort.Strings(out)
	return out
}

func cleanReason(reason string) string {
	reason = strings.TrimSpace(reason)
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, reason)
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > 500 {
		return reason[:500]
	}
	return reason
}

func validateIdentity(sessionID, environment string) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("session id is required")
	}
	if strings.TrimSpace(environment) == "" {
		return errors.New("environment is required")
	}
	return nil
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
