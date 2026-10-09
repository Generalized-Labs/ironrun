//go:build darwin

package envset

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type nativeStore struct{}

func newNativeStore() (ValueStore, error) {
	if _, err := exec.LookPath("security"); err != nil {
		return nil, err
	}
	return nativeStore{}, nil
}
func (nativeStore) Name() string                { return "macOS Keychain" }
func (nativeStore) service(scope string) string { return "ironrun/env/" + scope }
func (s nativeStore) Set(scope, key, value string) error {
	if err := validateName(key); err != nil {
		return err
	}
	service := s.service(scope)
	if strings.ContainsAny(service+key, " \t\r\n\"'\\") {
		return fmt.Errorf("keychain service %q is not safe for interactive input", service)
	}
	// The security CLI ignores piped input for its interactive -w prompt and can
	// silently store an empty value. -X is its deterministic binary-data input;
	// encoding prevents the credential from being parsed as an option or text.
	// The command goes to `security -i` on stdin so the credential never sits
	// in argv, where process listings and endpoint telemetry can read it.
	line := fmt.Sprintf("add-generic-password -U -s %s -a %s -X %s\n", service, key, hex.EncodeToString([]byte(value)))
	c := exec.Command("security", "-i")
	c.Stdin = strings.NewReader(line)
	out, err := c.CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) > 0 {
		return fmt.Errorf("keychain write failed: %s", safeOutput(out))
	}
	// Interactive mode exits 0 even when a command fails (for example on a
	// locked keychain), so confirm the write by reading it back.
	if stored, err := s.Get(scope, key); err != nil || stored != value {
		return errors.New("keychain write could not be verified")
	}
	return nil
}
func (s nativeStore) Get(scope, key string) (string, error) {
	if err := validateName(key); err != nil {
		return "", err
	}
	out, err := exec.Command("security", "find-generic-password", "-s", s.service(scope), "-a", key, "-w").Output()
	if err != nil {
		return "", ErrMissing
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
func (s nativeStore) Delete(scope, key string) error {
	if err := validateName(key); err != nil {
		return err
	}
	out, err := exec.Command("security", "delete-generic-password", "-s", s.service(scope), "-a", key).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "could not be found") {
		return fmt.Errorf("keychain delete failed: %s", safeOutput(out))
	}
	return nil
}
func (nativeStore) DeleteScope(scope string) error { return nil }
