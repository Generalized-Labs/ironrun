package tests

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// A binary that emits a base64- or hex-encoded form of a secret would defeat a
// literal-only redactor. The runner now registers encoded variants, so these
// forms must be redacted too.
func TestExfil_EncodedForms(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(exfilSecret))
	hexed := hex.EncodeToString([]byte(exfilSecret))

	tmp, err := os.CreateTemp("", "ironrun-encoded-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("b64=" + b64 + " hex=" + hexed + " end"); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	out, _, _, runErr := runWithSecret(t, "cat", tmp.Name())
	if runErr != nil {
		t.Skip("cat not available:", runErr)
	}
	if strings.Contains(out, b64) {
		t.Errorf("base64-encoded secret leaked through redactor: %q", out)
	}
	if strings.Contains(out, hexed) {
		t.Errorf("hex-encoded secret leaked through redactor: %q", out)
	}
}
