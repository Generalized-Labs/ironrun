package execution

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/policy"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestResolveSeccomp_IgnoresLegacyEnvKillSwitch(t *testing.T) {
	t.Setenv("IRONRUN_SECCOMP", "off") // dead kill-switch: must be ignored
	f := &policy.File{}
	cmd := &policy.Command{} // no per-command/policy setting -> default on
	var got bool
	stderr := captureStderr(t, func() { got = resolveSeccomp(f, cmd, false) })
	if !got {
		t.Error("IRONRUN_SECCOMP=off must be ignored; policy default (on) should win")
	}
	if !strings.Contains(stderr, "no longer honored") {
		t.Errorf("expected loud warning about the dead env var, got %q", stderr)
	}
}

func TestResolveSeccomp_DisableFlagWeakensLoudly(t *testing.T) {
	f := &policy.File{}
	cmd := &policy.Command{}
	var got bool
	stderr := captureStderr(t, func() { got = resolveSeccomp(f, cmd, true) })
	if got {
		t.Error("DisableSeccomp=true should turn the filter off")
	}
	if !strings.Contains(stderr, "SECURITY WARNING") || !strings.Contains(stderr, "--disable-seccomp") {
		t.Errorf("expected loud SECURITY WARNING for --disable-seccomp, got %q", stderr)
	}
}

func TestResolveSeccomp_PolicyOptOutRespected(t *testing.T) {
	off := false
	f := &policy.File{}
	cmd := &policy.Command{Seccomp: &off}
	stderr := captureStderr(t, func() {
		if resolveSeccomp(f, cmd, false) {
			t.Error("per-command seccomp: false should opt out")
		}
	})
	if strings.Contains(stderr, "SECURITY WARNING") {
		t.Errorf("policy opt-out is not a weakening; should not warn loudly, got %q", stderr)
	}
}
