package provider

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestHelperProcess is invoked as a fake CLI by fakeExec. It emits canned
// stdout/stderr and exit code driven by environment variables, so provider
// Resolve/Check paths can be tested without the real op/vault/doppler/infisical
// binaries installed.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if out := os.Getenv("GO_HELPER_STDOUT"); out != "" {
		os.Stdout.WriteString(out)
	}
	if errOut := os.Getenv("GO_HELPER_STDERR"); errOut != "" {
		os.Stderr.WriteString(errOut)
	}
	code := 0
	if os.Getenv("GO_HELPER_MODE") == "fail" {
		code = 1
	}
	os.Exit(code)
}

// fakeExec returns an execCommand stand-in whose child process is this test
// binary re-invoked into TestHelperProcess with canned behavior.
func fakeExec(mode, stdout, stderr string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		cs := append([]string{"-test.run=TestHelperProcess", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			"GO_HELPER_MODE=" + mode,
			"GO_HELPER_STDOUT=" + stdout,
			"GO_HELPER_STDERR=" + stderr,
		}
		return cmd
	}
}

func found(file string) (string, error) { return "/usr/local/bin/" + file, nil }
func notFound(string) (string, error)   { return "", exec.ErrNotFound }

// stubExec swaps lookPath/execCommand for the duration of the test.
func stubExec(t *testing.T, lp func(string) (string, error), ec func(string, ...string) *exec.Cmd) {
	t.Helper()
	origLP, origEC := lookPath, execCommand
	lookPath, execCommand = lp, ec
	t.Cleanup(func() { lookPath, execCommand = origLP, origEC })
}

// --- Check(): CLI missing ---

func TestCheck_CLIMissing(t *testing.T) {
	cases := []struct {
		p       HealthChecker
		wantErr error
	}{
		{&onePasswordProvider{}, ErrOpMissing},
		{&vaultProvider{}, ErrVaultMissing},
		{&dopplerProvider{}, ErrDopplerMissing},
		{&infisicalProvider{}, ErrInfisicalMissing},
	}
	for _, tc := range cases {
		stubExec(t, notFound, fakeExec("ok", "", ""))
		if err := tc.p.Check(); !errors.Is(err, tc.wantErr) {
			t.Errorf("Check() = %v, want %v", err, tc.wantErr)
		}
	}
}

// --- Check(): installed + authenticated ---

func TestCheck_OK(t *testing.T) {
	for _, p := range []HealthChecker{&onePasswordProvider{}, &vaultProvider{}, &dopplerProvider{}, &infisicalProvider{}} {
		stubExec(t, found, fakeExec("ok", "", ""))
		if err := p.Check(); err != nil {
			t.Errorf("Check() = %v, want nil", err)
		}
	}
}

// --- Check(): installed but not authenticated ---

func TestCheck_AuthFail(t *testing.T) {
	stubExec(t, found, fakeExec("fail", "", "not signed in"))
	if err := (&onePasswordProvider{}).Check(); !errors.Is(err, ErrOpAuth) {
		t.Errorf("op Check() = %v, want ErrOpAuth", err)
	}
	stubExec(t, found, fakeExec("fail", "", "missing client token"))
	if err := (&vaultProvider{}).Check(); !errors.Is(err, ErrVaultAuth) {
		t.Errorf("vault Check() = %v, want ErrVaultAuth", err)
	}
	stubExec(t, found, fakeExec("fail", "", "unauthorized"))
	if err := (&dopplerProvider{}).Check(); err == nil {
		t.Error("doppler Check() = nil, want auth error")
	}
}

// --- Resolve(): happy path returns the value ---

func TestResolve_OK(t *testing.T) {
	stubExec(t, found, fakeExec("ok", "secret-value\n", ""))
	if v, err := (&vaultProvider{}).Resolve("vault://secret/app#KEY"); err != nil || v != "secret-value" {
		t.Errorf("vault Resolve = %q, %v; want \"secret-value\", nil", v, err)
	}
	stubExec(t, found, fakeExec("ok", "op-secret", ""))
	if v, err := (&onePasswordProvider{}).Resolve("op://v/i/f"); err != nil || v != "op-secret" {
		t.Errorf("op Resolve = %q, %v; want \"op-secret\", nil", v, err)
	}
	stubExec(t, found, fakeExec("ok", "dop-secret\n", ""))
	if v, err := (&dopplerProvider{}).Resolve("API_KEY"); err != nil || v != "dop-secret" {
		t.Errorf("doppler Resolve = %q, %v; want \"dop-secret\", nil", v, err)
	}
}

// --- Resolve(): auth errors map to typed errors ---

func TestResolve_AuthError(t *testing.T) {
	stubExec(t, found, fakeExec("fail", "", "[ERROR] permission denied"))
	if _, err := (&vaultProvider{}).Resolve("vault://secret/app#KEY"); !errors.Is(err, ErrVaultAuth) {
		t.Errorf("vault Resolve err = %v, want ErrVaultAuth", err)
	}
	stubExec(t, found, fakeExec("fail", "", "you are not signed in"))
	if _, err := (&onePasswordProvider{}).Resolve("op://v/i/f"); !errors.Is(err, ErrOpAuth) {
		t.Errorf("op Resolve err = %v, want ErrOpAuth", err)
	}
}

// --- Resolve(): generic CLI failure surfaces as ErrResolve ---

func TestResolve_GenericFailure(t *testing.T) {
	stubExec(t, found, fakeExec("fail", "", "secret not found at path"))
	if _, err := (&vaultProvider{}).Resolve("vault://secret/app#KEY"); !errors.Is(err, ErrResolve) {
		t.Errorf("vault Resolve err = %v, want ErrResolve", err)
	}
}
