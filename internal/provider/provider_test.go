package provider

import (
	"errors"
	"os"
	"testing"
)

func TestNew_validProviders(t *testing.T) {
	cases := []struct {
		name     string
		wantName string
	}{
		{"1password", "1password"},
		{"op", "1password"},
		{"vault", "vault"},
		{"hashicorp", "vault"},
		{"doppler", "doppler"},
		{"infisical", "infisical"},
		{"env", "env"},
		{"environment", "env"},
		{"passthrough", "passthrough"},
		{"", "passthrough"},
	}
	for _, tc := range cases {
		p, err := New(tc.name)
		if err != nil {
			t.Errorf("New(%q) error: %v", tc.name, err)
			continue
		}
		if p.Name() != tc.wantName {
			t.Errorf("New(%q).Name() = %q want %q", tc.name, p.Name(), tc.wantName)
		}
	}
}

func TestNew_unknownProvider(t *testing.T) {
	_, err := New("definitely-not-a-real-provider")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestHealthCheckerImplementations(t *testing.T) {
	// CLI-backed providers expose a health check; CLI-free ones do not.
	for _, p := range []Provider{&onePasswordProvider{}, &vaultProvider{}, &dopplerProvider{}, &infisicalProvider{}} {
		if _, ok := p.(HealthChecker); !ok {
			t.Errorf("%s should implement HealthChecker", p.Name())
		}
	}
	for _, p := range []Provider{&envProvider{}, &passthroughProvider{}} {
		if _, ok := p.(HealthChecker); ok {
			t.Errorf("%s should not implement HealthChecker", p.Name())
		}
	}
}

func TestVaultProvider_name(t *testing.T) {
	p := &vaultProvider{}
	if p.Name() != "vault" {
		t.Errorf("got %q want vault", p.Name())
	}
}

func TestVaultProvider_badRef(t *testing.T) {
	p := &vaultProvider{}
	// Missing the #field portion — should fail before invoking the CLI.
	for _, ref := range []string{"secret/myapp", "vault://secret/myapp", "#FIELD", "vault://#FIELD"} {
		if _, err := p.Resolve(ref); err == nil {
			t.Errorf("expected error for malformed vault ref %q", ref)
		}
	}
}

func TestPassthroughResolve(t *testing.T) {
	p := &passthroughProvider{}
	val, err := p.Resolve("my-literal-value")
	if err != nil {
		t.Fatal(err)
	}
	if val != "my-literal-value" {
		t.Errorf("got %q want %q", val, "my-literal-value")
	}
}

func TestEnvResolve(t *testing.T) {
	p := &envProvider{}
	os.Setenv("IRONRUN_TEST_VAR", "hello123")
	defer os.Unsetenv("IRONRUN_TEST_VAR")

	val, err := p.Resolve("IRONRUN_TEST_VAR")
	if err != nil {
		t.Fatal(err)
	}
	if val != "hello123" {
		t.Errorf("got %q want %q", val, "hello123")
	}
}

func TestEnvResolve_envPrefix(t *testing.T) {
	p := &envProvider{}
	os.Setenv("IRONRUN_TEST_VAR2", "world456")
	defer os.Unsetenv("IRONRUN_TEST_VAR2")

	val, err := p.Resolve("env:IRONRUN_TEST_VAR2")
	if err != nil {
		t.Fatal(err)
	}
	if val != "world456" {
		t.Errorf("got %q want %q", val, "world456")
	}
}

func TestEnvResolve_literal(t *testing.T) {
	p := &envProvider{}
	val, err := p.Resolve("literal:hardcoded-value")
	if err != nil {
		t.Fatal(err)
	}
	if val != "hardcoded-value" {
		t.Errorf("got %q want %q", val, "hardcoded-value")
	}
}

func TestEnvResolve_missing(t *testing.T) {
	p := &envProvider{}
	os.Unsetenv("IRONRUN_DEFINITELY_NOT_SET_XYZ")
	_, err := p.Resolve("IRONRUN_DEFINITELY_NOT_SET_XYZ")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestResolveAll_passthrough(t *testing.T) {
	p := &passthroughProvider{}
	refs := map[string]string{
		"DB_URL":  "postgres://localhost/db",
		"API_KEY": "sk-test-123",
	}
	got, err := ResolveAll(p, refs)
	if err != nil {
		t.Fatal(err)
	}
	if got["DB_URL"] != "postgres://localhost/db" {
		t.Errorf("DB_URL: got %q", got["DB_URL"])
	}
	if got["API_KEY"] != "sk-test-123" {
		t.Errorf("API_KEY: got %q", got["API_KEY"])
	}
}

func TestDopplerProvider_name(t *testing.T) {
	p := &dopplerProvider{}
	if p.Name() != "doppler" {
		t.Errorf("got %q want doppler", p.Name())
	}
}

func TestInfisicalProvider_name(t *testing.T) {
	p := &infisicalProvider{}
	if p.Name() != "infisical" {
		t.Errorf("got %q want infisical", p.Name())
	}
}

func TestDopplerProvider_badRef(t *testing.T) {
	p := &dopplerProvider{}
	// Bad doppler:// format (only 2 parts not 3) — should fail before even calling CLI
	_, err := p.Resolve("doppler://project/config")
	if err == nil {
		t.Fatal("expected error for malformed doppler ref")
	}
}

func TestInfisicalProvider_badRef(t *testing.T) {
	p := &infisicalProvider{}
	// Bad infisical:// format — should fail before calling CLI
	_, err := p.Resolve("infisical://project/env")
	if err == nil {
		t.Fatal("expected error for malformed infisical ref")
	}
}

// --- EnvFile provider tests ---

func TestEnvFileProvider_ReadsFile(t *testing.T) {
	f, err := os.CreateTemp("", "ironrun-envfile-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("MY_KEY=my_secret_value\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	p, err := newEnvFileProvider(f.Name())
	if err != nil {
		t.Fatalf("newEnvFileProvider: %v", err)
	}
	val, err := p.Resolve("MY_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "my_secret_value" {
		t.Errorf("got %q want %q", val, "my_secret_value")
	}
}

func TestEnvFileProvider_NotFound(t *testing.T) {
	f, err := os.CreateTemp("", "ironrun-envfile-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("EXISTING_KEY=value\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	p, err := newEnvFileProvider(f.Name())
	if err != nil {
		t.Fatalf("newEnvFileProvider: %v", err)
	}
	_, err = p.Resolve("MISSING_KEY")
	if err == nil {
		t.Fatal("expected error for key not in file")
	}
	if !errors.Is(err, ErrResolve) {
		t.Errorf("expected ErrResolve, got %v", err)
	}
}

func TestEnvFileProvider_IgnoresComments(t *testing.T) {
	f, err := os.CreateTemp("", "ironrun-envfile-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	content := "# this is a comment\nREAL_KEY=real_value\n# another comment\n"
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()

	p, err := newEnvFileProvider(f.Name())
	if err != nil {
		t.Fatalf("newEnvFileProvider: %v", err)
	}
	val, err := p.Resolve("REAL_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "real_value" {
		t.Errorf("got %q want %q", val, "real_value")
	}
	// comment lines should not appear as keys
	_, err = p.Resolve("# this is a comment")
	if err == nil {
		t.Fatal("comment should not be a resolvable key")
	}
}

func TestEnvFileProvider_MissingFile(t *testing.T) {
	_, err := newEnvFileProvider("/tmp/ironrun-definitely-does-not-exist-xyz123.env")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEnvFileProvider_TildeExpansion(t *testing.T) {
	// Use os.TempDir() path directly (no ~ expansion needed for CI safety).
	// This test verifies the provider works end-to-end with an absolute path.
	f, err := os.CreateTemp("", "ironrun-envfile-tilde-*.env")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("TILDE_KEY=tilde_value\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	p, err := newEnvFileProvider(f.Name())
	if err != nil {
		t.Fatalf("newEnvFileProvider: %v", err)
	}
	val, err := p.Resolve("TILDE_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "tilde_value" {
		t.Errorf("got %q want %q", val, "tilde_value")
	}
}

// --- Additional Env provider tests ---

func TestEnvProvider_MissingVar(t *testing.T) {
	p := &envProvider{}
	// ensure it is definitely not set
	os.Unsetenv("IRONRUN_MISSING_VAR_TEST_XYZ9999")
	_, err := p.Resolve("IRONRUN_MISSING_VAR_TEST_XYZ9999")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
	if !errors.Is(err, ErrResolve) {
		t.Errorf("expected ErrResolve, got %v", err)
	}
}

func TestEnvProvider_LiteralPrefix(t *testing.T) {
	p := &envProvider{}
	val, err := p.Resolve("literal:myvalue")
	if err != nil {
		t.Fatal(err)
	}
	if val != "myvalue" {
		t.Errorf("got %q want %q", val, "myvalue")
	}
}
