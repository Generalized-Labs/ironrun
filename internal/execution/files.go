package execution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const staleRunAge = 24 * time.Hour

type fileWorkspace struct {
	dir     string
	created map[string]struct{}
}

func newFileWorkspace() (*fileWorkspace, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(cache, "ironrun", "run")
	if err := os.MkdirAll(base, 0700); err != nil {
		return nil, fmt.Errorf("create runtime directory: %w", err)
	}
	if err := os.Chmod(base, 0700); err != nil {
		return nil, fmt.Errorf("secure runtime directory: %w", err)
	}
	_ = cleanupStaleFileWorkspaces(base, time.Now())
	// Tag the run directory with the owning ironrun PID so stale recovery can
	// reclaim crash remnants promptly (dead owner) without ever deleting a live
	// run's directory, independent of the age fallback.
	dir, err := os.MkdirTemp(base, fmt.Sprintf("run-%d-", os.Getpid()))
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &fileWorkspace{dir: dir, created: map[string]struct{}{}}, nil
}

func (w *fileWorkspace) Materialize(filename string, value []byte) (string, error) {
	if filename == "" || filepath.Base(filename) != filename || filename == "." || filename == ".." || strings.ContainsAny(filename, `/\\`) {
		return "", errors.New("file secret filename must be a safe basename")
	}
	if w.created == nil {
		w.created = map[string]struct{}{}
	}
	if _, exists := w.created[filename]; exists {
		return "", fmt.Errorf("duplicate file secret filename %q", filename)
	}
	path := filepath.Join(w.dir, filename)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("materialize file secret: %w", err)
	}
	if _, err := f.Write(value); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("materialize file secret: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("materialize file secret: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	w.created[filename] = struct{}{}
	return path, nil
}

func (w *fileWorkspace) Close() error {
	if w == nil || w.dir == "" {
		return nil
	}
	err := os.RemoveAll(w.dir)
	w.dir = ""
	return err
}

func cleanupStaleFileWorkspaces(base string, now time.Time) error {
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		path := filepath.Join(base, entry.Name())
		info, err := os.Lstat(path)
		// Never touch symlinks or group/world-accessible dirs: not ours to trust.
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			continue
		}
		pid, hasPID := runDirOwnerPID(entry.Name())
		var remove bool
		switch {
		case hasPID && processAlive(pid):
			// A live run — NEVER reclaim it, regardless of age, or we would
			// delete a long-running command's file secrets out from under it.
			remove = false
		case hasPID:
			// Owner is gone: a crash remnant, reclaim promptly.
			remove = true
		default:
			// Legacy directory with no owner PID: fall back to the age rule.
			remove = now.Sub(info.ModTime()) >= staleRunAge
		}
		if !remove {
			continue
		}
		_ = os.RemoveAll(path)
	}
	return nil
}

// runDirOwnerPID extracts the owning ironrun PID from a run directory named
// "run-<pid>-<rand>". hasPID is false for older "run-<rand>" layouts, which
// fall back to the age rule.
func runDirOwnerPID(name string) (pid int, hasPID bool) {
	rest := strings.TrimPrefix(name, "run-")
	i := strings.IndexByte(rest, '-')
	if i <= 0 {
		return 0, false
	}
	p, err := strconv.Atoi(rest[:i])
	if err != nil || p <= 0 {
		return 0, false
	}
	return p, true
}

// CleanupStale removes validated Ironrun-owned crash remnants. Unknown paths,
// symlinks, permissive directories, and recent runs are always left alone.
func CleanupStale() error {
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	base := filepath.Join(cache, "ironrun", "run")
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return cleanupStaleFileWorkspaces(base, time.Now())
}
