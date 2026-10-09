package runner_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/generalized-labs/ironrun/internal/runner"
)

// buildProcfix compiles the testdata/procfix multi-mode fixture.
func buildProcfix(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("procfix fixture is Unix-only")
	}
	bin := filepath.Join(t.TempDir(), "procfix")
	if out, err := exec.Command("go", "build", "-o", bin, "./testdata/procfix").CombinedOutput(); err != nil {
		t.Fatalf("build procfix fixture: %v\n%s", err, out)
	}
	return bin
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A timed-out command must kill the WHOLE process group, not just the direct
// child: a grandchild left running would still hold the injected secrets.
func TestRun_TTLKillsGrandchildren(t *testing.T) {
	bin := buildProcfix(t)
	marker := filepath.Join(t.TempDir(), "marker")
	cmd := makeCmd("spawn", "500ms", bin, "spawn-grandchild", marker)
	start := time.Now()
	_, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Run blocked %v past its 500ms TTL", elapsed)
	}
	// The grandchild sleeps 3s before writing; after the group kill it must
	// never get there.
	time.Sleep(3500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("grandchild survived the group kill and wrote its marker")
	}
}

// A grandchild holding the output pipe open must not wedge Wait: WaitDelay
// bounds the post-exit wait so Run always returns.
func TestRun_GrandchildHoldingPipeDoesNotBlockRun(t *testing.T) {
	bin := buildProcfix(t)
	cmd := makeCmd("holdpipe", "", bin, "hold-pipe") // no TTL
	done := make(chan struct{})
	start := time.Now()
	go func() {
		_, _ = runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
		close(done)
	}()
	select {
	case <-done:
		t.Logf("Run returned in %v (grandchild held the pipe for 60s)", time.Since(start).Round(100*time.Millisecond))
	case <-time.After(15 * time.Second):
		t.Fatal("Run blocked on a grandchild holding the output pipe")
	}
}

// A signal-killed child reports the POSIX 128+signo exit code, not a bare -1.
func TestRun_SignalKilledChildExitCode(t *testing.T) {
	bin := buildProcfix(t)
	cmd := makeCmd("selfsig", "", bin, "self-signal", "15") // SIGTERM
	res, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 128+15 {
		t.Errorf("signal-killed child exit code = %d, want %d", res.ExitCode, 128+15)
	}
}

// A context cancellation must surface as an error, never a silent nil/-1.
func TestRun_ContextCancelReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	cmd := makeCmd("sleep", "", "sleep", "10") // no TTL
	res, err := runner.Run(ctx, cmd, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if !errors.Is(err, runner.ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got err=%v res=%v", err, res)
	}
}

// Truncated must be true only when bytes were actually dropped — not when the
// output merely reaches the cap exactly.
func TestRun_MaxBytesTruncatedOnlyWhenDropped(t *testing.T) {
	bin := buildProcfix(t)

	exact := makeCmd("exact", "", bin, "emit", "100")
	exact.MaxBytes = 100
	res, err := runner.Run(context.Background(), exact, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Error("output exactly at max_bytes was reported Truncated (nothing was dropped)")
	}

	over := makeCmd("over", "", bin, "emit", "101")
	over.MaxBytes = 100
	res, err = runner.Run(context.Background(), over, runner.Options{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Error("output past max_bytes was not reported Truncated")
	}
}

// A broken output sink (the consumer of ironrun's stdout went away, e.g.
// `… | head`) must end the run and still run cleanup, not wedge Wait forever.
func TestRun_BrokenOutputSinkEndsRunAndCleansUp(t *testing.T) {
	bin := buildProcfix(t)
	cmd := makeCmd("stream", "", bin, "stream") // infinite output, no TTL
	cleaned := make(chan struct{}, 1)
	sink := writerFunc(func(p []byte) (int, error) { return 0, errors.New("broken pipe") })
	done := make(chan struct{})
	go func() {
		_, _ = runner.Run(context.Background(), cmd, runner.Options{
			Stdout:  sink,
			Stderr:  io.Discard,
			Cleanup: func() error { cleaned <- struct{}{}; return nil },
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not end after the output sink broke")
	}
	select {
	case <-cleaned:
	default:
		t.Error("cleanup did not run after the output sink broke")
	}
}

// A target exiting 124/125 must NOT be misreported as a sealed-exec shim
// refusal when the shim was never armed for the run.
func TestRun_LegitExit124NotMisreportedAsShimRefusal(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("on Linux the shim is armed, so 124/125 genuinely are its refusal codes")
	}
	bin := buildProcfix(t)
	seccomp := true
	for _, code := range []string{"124", "125"} {
		cmd := makeCmd("exit", "", bin, "exit", code)
		res, err := runner.Run(context.Background(), cmd, runner.Options{
			Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Seccomp: &seccomp,
		})
		if err != nil {
			t.Fatalf("exit %s: %v", code, err)
		}
		if strings.Contains(res.SeccompDetail, "shim refused") {
			t.Errorf("exit %s misreported as a shim refusal: %q", code, res.SeccompDetail)
		}
	}
}

// A relative workdir resolves against the project root (opts.WorkDir), not
// ironrun's own process cwd.
func TestRun_RelativeWorkDirUsesProjectRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "api"), 0o700); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "services", "api"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(elsewhere)

	cmd := makeCmd("pwd", "", "pwd")
	cmd.WorkDir = "services/api"
	var out bytes.Buffer
	if _, err := runner.Run(context.Background(), cmd, runner.Options{Stdout: &out, Stderr: &bytes.Buffer{}, WorkDir: root}); err != nil {
		t.Fatal(err)
	}
	got, err := filepath.EvalSymlinks(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(root, "services", "api"))
	if got != want {
		t.Errorf("relative workdir resolved to %q, want project-root-relative %q", got, want)
	}
}
