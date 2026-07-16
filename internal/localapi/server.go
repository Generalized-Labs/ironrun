// Package localapi exposes Ironrun's value-blind control plane over an
// owner-only Unix socket. It intentionally has no plaintext secret endpoint.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/audit"
	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/execution"
	"github.com/generalized-labs/ironrun/internal/policy"
)

type Server struct {
	policy     *policy.File
	policyPath string
	root       string
	access     *access.Manager
	audit      *audit.Logger
	sessionID  string
}

type runRequest struct {
	CommandID   string `json:"command_id"`
	Environment string `json:"environment,omitempty"`
}

func New(f *policy.File, policyPath, root string) (*Server, error) {
	manager, err := access.Open(root)
	if err != nil {
		return nil, err
	}
	auditLog, err := audit.Open(audit.ResolvePath(f.AuditLog))
	if err != nil {
		return nil, err
	}
	return &Server{
		policy: f, policyPath: policyPath, root: root, access: manager,
		audit: auditLog, sessionID: "local-api-" + audit.NewSessionID(),
	}, nil
}

func (s *Server) Close() error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/environments", s.environments)
	mux.HandleFunc("GET /v1/access/requests", s.requests)
	mux.HandleFunc("GET /v1/access/leases", s.leases)
	mux.HandleFunc("POST /v1/run", s.run)
	mux.HandleFunc("POST /v1/access/requests/{id}/deny", s.denyRequest)
	mux.HandleFunc("POST /v1/access/leases/{id}/revoke", s.revokeLease)
	return securityHeaders(mux)
}

func Serve(ctx context.Context, f *policy.File, policyPath, root, socketPath string) error {
	if err := prepareSocket(socketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on local socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath) //nolint:errcheck
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("secure local socket: %w", err)
	}
	server, err := New(f, policyPath, root)
	if err != nil {
		return err
	}
	defer server.Close()
	httpServer := &http.Server{
		Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func prepareSocket(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	return os.Remove(path)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	environment := "default"
	if s.policy.UsesEnvironmentEntries() || s.policy.EnvironmentSet == "active" {
		if manager, err := envset.Open(s.root); err == nil {
			if active, err := manager.Active(); err == nil {
				environment = active.Name
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "environment": environment,
		"commands": len(s.policy.Commands), "require_agent_leases": s.policy.RequireAgentLeases,
		"secret_values_exposed": false,
	})
}

func (s *Server) environments(w http.ResponseWriter, r *http.Request) {
	if !s.policy.UsesEnvironmentEntries() && s.policy.EnvironmentSet != "active" {
		writeJSON(w, http.StatusOK, []map[string]any{{"name": "default", "active": true, "provider_backed": true}})
		return
	}
	manager, err := envset.Open(s.root)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "environment store unavailable")
		return
	}
	out := make([]map[string]any, 0, len(manager.Meta.Sets))
	for _, name := range manager.Names() {
		set, _ := manager.Set(name)
		entries := make([]map[string]any, 0, len(set.Entries))
		for _, entry := range set.Entries {
			entries = append(entries, map[string]any{
				"name": entry.Name, "kind": entry.Kind, "target": entry.Target,
				"filename": entry.Filename, "configured": true,
			})
		}
		out = append(out, map[string]any{
			"name": name, "active": name == manager.Meta.Active, "temporary": set.Temporary,
			"configured_keys": len(set.Keys), "configured_items": len(set.Entries), "entries": entries,
			"expires_at": set.ExpiresAt, "expired": manager.Expired(set),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) requests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.access.Requests()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access state unavailable")
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) leases(w http.ResponseWriter, r *http.Request) {
	leases, err := s.access.Leases("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "access state unavailable")
		return
	}
	writeJSON(w, http.StatusOK, leases)
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	var request runRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	if strings.TrimSpace(request.CommandID) == "" {
		writeError(w, http.StatusBadRequest, "command_id is required")
		return
	}
	if _, err := s.policy.Lookup(request.CommandID); err != nil {
		writeError(w, http.StatusNotFound, "command is not in the policy")
		return
	}
	result, err := execution.Run(r.Context(), s.policy, s.policyPath, s.root, request.CommandID, execution.Options{
		Environment: request.Environment, Stdout: io.Discard, Stderr: io.Discard,
		Audit: s.audit, SessionID: s.sessionID,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "sealed execution failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exit_code": result.ExitCode, "stdout": result.Stdout, "stderr": result.Stderr,
		"duration_ms": result.DurationMs, "truncated": result.Truncated,
		"entropy_warnings": result.EntropyWarnings,
	})
}

func (s *Server) denyRequest(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(w, r); err != nil {
		return
	}
	if err := s.access.Deny(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "pending request not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
}

func (s *Server) revokeLease(w http.ResponseWriter, r *http.Request) {
	if err := requireEmptyBody(w, r); err != nil {
		return
	}
	if err := s.access.Revoke(r.PathValue("id"), ""); err != nil {
		writeError(w, http.StatusNotFound, "lease not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain one JSON object")
		return errors.New("trailing JSON")
	}
	return nil
}

func requireEmptyBody(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) != 0 {
		writeError(w, http.StatusBadRequest, "request body must be empty")
		return errors.New("non-empty request body")
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
