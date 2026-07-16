//go:build !windows

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonOwnerSocketAndHealth(t *testing.T) {
	home := filepath.Join("/tmp", fmt.Sprintf("ironrun-daemon-%d", time.Now().UnixNano()))
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("IRONRUN_HOME", home)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := Ping(pingCtx)
		pingCancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not become healthy: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	socket, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v", info.Mode())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestUnitPreviewContainsOnlyExecutableMetadata(t *testing.T) {
	path, content, err := UnitPreview()
	if err != nil {
		t.Fatal(err)
	}
	if path == "" || content == "" {
		t.Fatal("service preview is empty")
	}
	for _, forbidden := range []string{"secret_value", "environment_value", "vault_key"} {
		if containsFold(content, forbidden) {
			t.Fatalf("service preview contains secret-adjacent field %q", forbidden)
		}
	}
}

func containsFold(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		chunk := value[i : i+len(want)]
		match := true
		for j := range chunk {
			a, b := chunk[j], want[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
