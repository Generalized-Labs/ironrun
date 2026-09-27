package policy

import "testing"

func dur(t *testing.T, s string) Duration {
	t.Helper()
	d := Duration{}
	if err := d.SetDuration(s); err != nil {
		t.Fatalf("bad duration %q: %v", s, err)
	}
	return d
}

func findingByCode(fs []Finding, code string) *Finding {
	for i := range fs {
		if fs[i].Code == code {
			return &fs[i]
		}
	}
	return nil
}

func TestLint_ShellArgv(t *testing.T) {
	f := &File{Commands: []Command{{ID: "x", Argv: []string{"bash", "-c", "echo hi"}, TTL: dur(t, "5s")}}}
	got := findingByCode(Lint(f), "SHELL_ARGV")
	if got == nil || got.Severity != SeverityError {
		t.Fatalf("expected SHELL_ARGV error, got %+v", got)
	}
}

func TestLint_InterpreterEvalWithSecretsIsError(t *testing.T) {
	bn := false
	f := &File{Commands: []Command{{
		ID:        "x",
		Argv:      []string{"/usr/bin/python3", "-c", "print(1)"},
		TTL:       dur(t, "5s"),
		NoNetwork: true,
		Env:       map[string]string{"API_KEY": "op://v/i/f"},
		Seccomp:   &bn,
	}}}
	fs := Lint(f)
	if got := findingByCode(fs, "INTERPRETER_ARBITRARY"); got == nil {
		t.Errorf("expected INTERPRETER_ARBITRARY")
	}
	if got := findingByCode(fs, "INTERPRETER_EVAL"); got == nil || got.Severity != SeverityError {
		t.Errorf("expected INTERPRETER_EVAL error (secrets injected), got %+v", got)
	}
}

func TestLint_NoTTL(t *testing.T) {
	f := &File{Commands: []Command{{ID: "x", Argv: []string{"go", "test"}, NoNetwork: true}}}
	if got := findingByCode(Lint(f), "NO_TTL"); got == nil || got.Severity != SeverityWarn {
		t.Errorf("expected NO_TTL warn, got %+v", got)
	}
}

func TestLint_EgressWithSecrets(t *testing.T) {
	f := &File{Commands: []Command{{
		ID:           "x",
		Argv:         []string{"go", "test"},
		TTL:          dur(t, "5m"),
		Env:          map[string]string{"DB": "op://v/i/f"},
		AllowNetwork: true, // explicit opt-out of the default deny
	}}}
	if got := findingByCode(Lint(f), "EGRESS_WITH_SECRETS"); got == nil || got.Severity != SeverityWarn {
		t.Errorf("expected EGRESS_WITH_SECRETS warn, got %+v", got)
	}
}

func TestLint_EgressWithSecretsDefaultDeny(t *testing.T) {
	// A secret-bearing command with no network setting is denied by default:
	// no EGRESS_WITH_SECRETS, but a NETWORK_DEFAULT_DENY warning nudging the
	// author to make the posture explicit (per the spec: lint warns when a
	// secret-bearing command lacks no_network).
	f := &File{Commands: []Command{{
		ID:   "x",
		Argv: []string{"go", "test"},
		TTL:  dur(t, "5m"),
		Env:  map[string]string{"DB": "op://v/i/f"},
	}}}
	if got := findingByCode(Lint(f), "EGRESS_WITH_SECRETS"); got != nil {
		t.Errorf("expected no EGRESS_WITH_SECRETS under default deny, got %+v", got)
	}
	if got := findingByCode(Lint(f), "NETWORK_DEFAULT_DENY"); got == nil || got.Severity != SeverityWarn {
		t.Errorf("expected NETWORK_DEFAULT_DENY warn, got %+v", got)
	}
}

func TestLint_NoSecretsNoNetworkFindings(t *testing.T) {
	f := &File{Commands: []Command{{
		ID:   "x",
		Argv: []string{"go", "test"},
		TTL:  dur(t, "5m"),
	}}}
	for _, code := range []string{"EGRESS_WITH_SECRETS", "NETWORK_DEFAULT_DENY"} {
		if got := findingByCode(Lint(f), code); got != nil {
			t.Errorf("expected no %s for secretless command, got %+v", code, got)
		}
	}
}

func TestLint_SecretInArgv(t *testing.T) {
	f := &File{Commands: []Command{{
		ID:        "x",
		Argv:      []string{"deploy", "--token", "sk_live_abc123def456ghi789"},
		TTL:       dur(t, "5m"),
		NoNetwork: true,
	}}}
	if got := findingByCode(Lint(f), "SECRET_IN_ARGV"); got == nil {
		t.Errorf("expected SECRET_IN_ARGV finding")
	}
}

func TestLint_SecretSpread(t *testing.T) {
	mk := func(id string) Command {
		return Command{ID: id, Argv: []string{"go", "test"}, TTL: dur(t, "5m"), NoNetwork: true,
			Env: map[string]string{"SHARED": "op://v/shared/key"}}
	}
	f := &File{Commands: []Command{mk("a"), mk("b"), mk("c"), mk("d")}} // 4 > 3
	if got := findingByCode(Lint(f), "SECRET_SPREAD"); got == nil || got.Severity != SeverityWarn {
		t.Errorf("expected SECRET_SPREAD warn, got %+v", got)
	}
}

func TestLint_CleanPolicyNoErrors(t *testing.T) {
	f := &File{Commands: []Command{{
		ID:        "build",
		Argv:      []string{"go", "build", "./..."},
		TTL:       dur(t, "5m"),
		NoNetwork: true,
	}}}
	for _, fi := range Lint(f) {
		if fi.Severity == SeverityError {
			t.Errorf("clean policy produced an error finding: %+v", fi)
		}
	}
}
