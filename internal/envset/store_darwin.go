//go:build darwin

package envset

import (
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
	c := exec.Command("security", "add-generic-password", "-U", "-s", s.service(scope), "-a", key, "-w")
	c.Stdin = strings.NewReader(value + "\n")
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain write failed: %s", safeOutput(out))
	}
	return nil
}
func (s nativeStore) Get(scope, key string) (string, error) {
	out, err := exec.Command("security", "find-generic-password", "-s", s.service(scope), "-a", key, "-w").Output()
	if err != nil {
		return "", ErrMissing
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
func (s nativeStore) Delete(scope, key string) error {
	out, err := exec.Command("security", "delete-generic-password", "-s", s.service(scope), "-a", key).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "could not be found") {
		return fmt.Errorf("keychain delete failed: %s", safeOutput(out))
	}
	return nil
}
func (s nativeStore) DeleteScope(scope string) error { return nil }
