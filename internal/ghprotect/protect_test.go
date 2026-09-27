package ghprotect

import (
	"strings"
	"testing"
)

func TestEnableRepoScanningRender(t *testing.T) {
	got := EnableRepoScanning("octo", "hello").Render()
	for _, want := range []string{
		"gh api --method PATCH 'repos/octo/hello'",
		"security_and_analysis[secret_scanning][status]=enabled",
		"security_and_analysis[secret_scanning_push_protection][status]=enabled",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("render missing %q:\n%s", want, got)
		}
	}
}

func TestOrgDefaultsRender(t *testing.T) {
	got := OrgDefaults("octo").Render()
	for _, want := range []string{
		"gh api --method PATCH 'orgs/octo'",
		"secret_scanning_enabled_for_new_repositories=true",
		"secret_scanning_push_protection_enabled_for_new_repositories=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("render missing %q:\n%s", want, got)
		}
	}
}

func TestCreateCustomPatternsRender(t *testing.T) {
	c, err := CreateCustomPatterns("octo", "hello", []Pattern{
		{Name: "internal-token", Regex: `INT-[A-Z0-9]{32}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := c.Render()
	for _, want := range []string{
		"POST 'repos/octo/hello/secret-scanning/custom-patterns'",
		"--input - <<'EOF'",
		`"name": "internal-token"`,
		`"pattern": "INT-[A-Z0-9]{32}"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("render missing %q:\n%s", want, got)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	ok := []Pattern{
		{Name: "internal", Regex: `INT-[A-Z0-9]{32}`},
		{Name: "webhook", Regex: `https://hooks\.internal/[A-Za-z0-9/_-]{20,}`},
	}
	for _, p := range ok {
		if err := ValidatePattern(p); err != nil {
			t.Fatalf("valid pattern rejected: %v", err)
		}
	}
	bad := []Pattern{
		{Name: "look", Regex: `AKIA(?=[A-Z0-9]{16})`},       // lookahead
		{Name: "lookbehind", Regex: `(?<=x)AKIA[0-9]+`},     // lookbehind
		{Name: "badregex", Regex: `AKIA([0-9]+`},            // invalid
		{Name: "", Regex: `AKIA[0-9]+`},                     // empty name
		{Name: "empty", Regex: ``},                          // empty regex
		{Name: "toolong", Regex: strings.Repeat("a", 1001)}, // too long
	}
	for _, p := range bad {
		if err := ValidatePattern(p); err == nil {
			t.Fatalf("invalid pattern accepted: %+v", p)
		}
	}
}

func TestCreateCustomPatternsValidatesAll(t *testing.T) {
	if _, err := CreateCustomPatterns("o", "r", nil); err == nil {
		t.Fatal("expected error with no patterns")
	}
	if _, err := CreateCustomPatterns("o", "r", []Pattern{{Name: "x", Regex: "ok[0-9]+/"}, {Name: "y", Regex: "([bad"}}); err == nil {
		t.Fatal("expected error when any pattern is invalid")
	}
}

func TestBypassPolicyChecklistHonest(t *testing.T) {
	items := BypassPolicyChecklist()
	if len(items) == 0 {
		t.Fatal("checklist empty")
	}
	joined := strings.Join(items, "\n")
	if !strings.Contains(joined, "Require bypass reason") {
		t.Fatal("checklist missing the bypass-reason step")
	}
}
