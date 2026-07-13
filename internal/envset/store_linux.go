//go:build linux

package envset

import (
	"fmt"
	"os/exec"
	"strings"
)

type nativeStore struct{}

func newNativeStore() (ValueStore, error) {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return nil, fmt.Errorf("install libsecret secret-tool")
	}
	return nativeStore{}, nil
}
func (nativeStore) Name() string { return "Linux Secret Service" }
func (nativeStore) args(scope, key string) []string {
	return []string{"service", "ironrun", "scope", scope, "key", key}
}
func (s nativeStore) Set(scope, key, value string) error {
	if err := validateName(key); err != nil {
		return err
	}
	args := append([]string{"store", "--label=ironrun environment"}, s.args(scope, key)...)
	c := exec.Command("secret-tool", args...)
	c.Stdin = strings.NewReader(value + "\n")
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("secret service write failed: %s", safeOutput(out))
	}
	return nil
}
func (s nativeStore) Get(scope, key string) (string, error) {
	out, err := exec.Command("secret-tool", append([]string{"lookup"}, s.args(scope, key)...)...).Output()
	if err != nil {
		return "", ErrMissing
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}
func (s nativeStore) Delete(scope, key string) error {
	out, err := exec.Command("secret-tool", append([]string{"clear"}, s.args(scope, key)...)...).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "not found") {
		return fmt.Errorf("secret service delete failed: %s", safeOutput(out))
	}
	return nil
}
func (s nativeStore) DeleteScope(scope string) error { return nil }
