//go:build unix

package execution

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/envset"
	"github.com/generalized-labs/ironrun/internal/policy"
)

// fileCapableStore adds file-secret support to the in-memory test store.
type fileCapableStore struct{ v2MemoryStore }

func (s *fileCapableStore) SetBytes(scope, key string, v []byte) error {
	return s.Set(scope, key, string(v))
}

// A live run's directory (owner process still alive) must survive stale
// recovery even when it is older than the age fallback — otherwise a long run
// would have its file secrets deleted out from under it.
func TestStaleCleanup_KeepsLiveRunDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, fmt.Sprintf("run-%d-live", os.Getpid()))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleFileWorkspaces(base, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("stale recovery deleted a live run's directory (owner alive): %v", err)
	}
}

// A crash remnant whose owning ironrun is dead must be reclaimed promptly, even
// when its mtime is recent (the age fallback would not catch it yet).
func TestStaleCleanup_RemovesDeadOwnerDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, fmt.Sprintf("run-%d-crash", deadPID(t)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupStaleFileWorkspaces(base, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("stale recovery kept a crash remnant whose owner is dead: %v", err)
	}
}

// Cancelling the run (what a SIGINT/SIGTERM becomes in the CLI/MCP) must still
// run file-secret cleanup, so no plaintext is left on disk.
func TestRun_CancelRemovesFileSecret(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no user cache dir")
	}
	runBase := filepath.Join(cacheBase, "ironrun", "run")

	root := t.TempDir()
	store := &fileCapableStore{v2MemoryStore{values: map[string]string{}}}
	m := &envset.Manager{Root: root, Store: store, Now: time.Now, Meta: envset.Metadata{Version: 2, Active: "dev", Identity: envset.Identity{CanonicalPath: root}, Sets: map[string]envset.Set{"dev": {Name: "dev", CreatedAt: time.Now()}}}}
	entry := envset.Entry{Name: "CREDS", Kind: envset.EntryFile, Target: "CREDS", Filename: "sa.json"}
	if err := m.PutEntry("dev", entry, []byte("PLAINTEXT-FILE-SECRET")); err != nil {
		t.Fatal(err)
	}
	orig := openEnvironment
	t.Cleanup(func() { openEnvironment = orig })
	openEnvironment = func(string) (*envset.Manager, error) { return m, nil }

	f := &policy.File{Version: policy.SupportedVersionV2, EnvironmentSet: "active", Commands: []policy.Command{{ID: "s", Argv: []string{"sleep", "30"}, Secrets: []string{"CREDS"}, AllowNetwork: true}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = Run(ctx, f, "ironrun.yml", root, "s", Options{Environment: "dev", Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		close(done)
	}()

	// Wait for the file secret to materialize, then cancel mid-run.
	var created []string
	for i := 0; i < 100 && len(created) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		created, _ = filepath.Glob(filepath.Join(runBase, "run-*", "sa.json"))
	}
	if len(created) == 0 {
		cancel()
		<-done
		t.Fatal("file secret never materialized")
	}
	cancel()
	<-done

	if leftover, _ := filepath.Glob(filepath.Join(runBase, "run-*", "sa.json")); len(leftover) != 0 {
		t.Errorf("cancelled run left file-secret plaintext behind: %v", leftover)
	}
}

// deadPID returns the PID of a process that has already exited.
func deadPID(t *testing.T) int {
	t.Helper()
	tp, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no `true` binary to source a dead PID")
	}
	c := exec.Command(tp)
	if err := c.Run(); err != nil {
		t.Fatalf("run true: %v", err)
	}
	return c.Process.Pid
}
