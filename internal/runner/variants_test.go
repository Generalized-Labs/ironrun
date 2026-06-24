package runner_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/generalized-labs/ironrun/internal/runner"
)

func TestSecretVariants_IncludesCommonEncodings(t *testing.T) {
	secret := "supersecretvalue" // 16 bytes
	set := map[string]bool{}
	for _, v := range runner.SecretVariants(secret) {
		if v == "" {
			t.Error("empty variant registered")
		}
		if set[v] {
			t.Errorf("duplicate variant: %q", v)
		}
		set[v] = true
	}
	want := []string{
		secret,
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)),
		hex.EncodeToString([]byte(secret)),
		strings.ToUpper(hex.EncodeToString([]byte(secret))),
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("expected variant %q to be registered", w)
		}
	}
}

func TestSecretVariants_ShortSecretSkipsHex(t *testing.T) {
	// A 4-byte secret hex-encodes to 8 chars — too collision-prone — so no hex.
	for _, v := range runner.SecretVariants("abcd") {
		if v == hex.EncodeToString([]byte("abcd")) {
			t.Errorf("hex variant wrongly registered for a short secret: %q", v)
		}
	}
}

func TestRun_EncodedSecretRedacted(t *testing.T) {
	secret := "ironrun-encoded-canary-value"
	b64 := base64.StdEncoding.EncodeToString([]byte(secret))
	// printf prints the BASE64 form as a literal arg. It is NOT an injected
	// secret — it is caught only because it is a registered ENCODING variant of
	// the injected literal secret.
	cmd := makeCmd("printf", "", "printf", "%s", b64)
	var out bytes.Buffer
	res, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &out,
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"IRONRUN_SECRET": secret},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(out.String(), b64) {
		t.Errorf("base64-encoded secret leaked: %q", out.String())
	}
	if res.RedactionCount < 1 {
		t.Errorf("expected >= 1 redaction, got %d", res.RedactionCount)
	}
}

func TestRun_ShortSecretHexNotFalsePositive(t *testing.T) {
	// "test" is 4 bytes (< the hex floor of 8) so its hex form is not registered;
	// an 8-hex string (e.g. a git short SHA) in output must pass through untouched.
	secret := "test"
	hexForm := hex.EncodeToString([]byte(secret)) // 74657374
	cmd := makeCmd("printf", "", "printf", "%s", hexForm)
	var out bytes.Buffer
	_, err := runner.Run(context.Background(), cmd, runner.Options{
		Stdout:  &out,
		Stderr:  &bytes.Buffer{},
		Secrets: map[string]string{"IRONRUN_SECRET": secret},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), hexForm) {
		t.Errorf("hex of a short secret was redacted (false positive): %q", out.String())
	}
}
