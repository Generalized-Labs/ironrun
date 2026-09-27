//go:build windows

package main

import (
	"strings"
	"testing"
)

// Regression test for the silent cleartext-input degradation: on Windows the
// old code ran `stty -echo`, discarded the error (stty does not exist on
// Windows), and read the secret with echo enabled. Windows is cut from the
// OSS launch, so ironrun must now fail loudly before any secret is read.
func TestReadSecretWindowsRefuses(t *testing.T) {
	for _, fromStdin := range []bool{false, true} {
		value, err := readSecret(fromStdin, false)
		if err == nil {
			t.Fatalf("readSecret(fromStdin=%v) on Windows: expected error, got none", fromStdin)
		}
		if value != "" {
			t.Fatalf("readSecret(fromStdin=%v) on Windows: expected no value, got %q", fromStdin, value)
		}
		if !strings.Contains(err.Error(), "Windows is not supported by ironrun") {
			t.Fatalf("readSecret(fromStdin=%v) on Windows: unexpected error message: %v", fromStdin, err)
		}
	}
}
