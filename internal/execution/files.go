package execution

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	dir, err := os.MkdirTemp(base, "run-")
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
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || now.Sub(info.ModTime()) < staleRunAge {
			continue
		}
		_ = os.RemoveAll(path)
	}
	return nil
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
