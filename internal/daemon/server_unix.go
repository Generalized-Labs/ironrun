//go:build !windows

// Package daemon serves Ironrun's value-blind per-user coordination API.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/generalized-labs/ironrun/internal/access"
	"github.com/generalized-labs/ironrun/internal/project"
)

func SocketPath() (string, error) {
	registry, err := project.DefaultStore()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(registry.Path), "ironrun.sock"), nil
}

func Serve(ctx context.Context) error {
	registry, err := project.DefaultStore()
	if err != nil {
		return err
	}
	socket, err := SocketPath()
	if err != nil {
		return err
	}
	if err := prepareSocket(socket); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen on global socket: %w", err)
	}
	checked := &peerListener{Listener: listener, uid: os.Getuid()}
	defer checked.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return fmt.Errorf("secure global socket: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		projects, _ := registry.List()
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "projects": len(projects), "secret_values_exposed": false})
	})
	mux.HandleFunc("GET /v1/projects", func(w http.ResponseWriter, r *http.Request) {
		projects, listErr := registry.List()
		if listErr != nil {
			writeError(w, http.StatusInternalServerError, "project registry unavailable")
			return
		}
		writeJSON(w, http.StatusOK, projects)
	})
	mux.HandleFunc("GET /v1/inbox", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, collectInbox(registry))
	})
	server := &http.Server{Handler: noStore(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err := server.Serve(checked); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func Ping(ctx context.Context) error {
	socket, err := SocketPath()
	if err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ironrun/v1/status", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %s", response.Status)
	}
	return nil
}

type inboxRecord struct {
	ProjectID   string         `json:"project_id"`
	ProjectName string         `json:"project_name"`
	Request     access.Request `json:"request"`
}

func collectInbox(registry *project.Store) []inboxRecord {
	projects, err := registry.List()
	if err != nil {
		return nil
	}
	var result []inboxRecord
	for _, p := range projects {
		if _, err := os.Stat(p.Path); err != nil {
			continue
		}
		manager, err := access.Open(p.Path)
		if err != nil {
			continue
		}
		requests, err := manager.Requests()
		if err != nil {
			continue
		}
		for _, request := range requests {
			if request.Status == access.StatusPending {
				result = append(result, inboxRecord{ProjectID: p.ID, ProjectName: p.Name, Request: request})
			}
		}
	}
	return result
}

type peerListener struct {
	net.Listener
	uid int
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(conn)
		if err == nil && uid == l.uid {
			return conn, nil
		}
		_ = conn.Close()
	}
}

func prepareSocket(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
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

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
