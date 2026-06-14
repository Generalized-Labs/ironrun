package provider

import (
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
	_, err := New("vault")
	if err == nil {
		t.Fatal("expected error for unknown provider")
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
