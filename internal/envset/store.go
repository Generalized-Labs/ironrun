// Package envset manages project-scoped environment sets. Values are only
// stored in an operating-system credential manager; this package never writes
// secret values to disk.
package envset

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

var (
	ErrMissing     = errors.New("environment key missing")
	ErrUnavailable = errors.New("native secure storage unavailable")
)

type ValueStore interface {
	Name() string
	Set(scope, key, value string) error
	Get(scope, key string) (string, error)
	Delete(scope, key string) error
	DeleteScope(scope string) error
}

func OpenNative() (ValueStore, error) {
	store, err := newNativeStore()
	if err != nil {
		return nil, fmt.Errorf("%w on %s: %v", ErrUnavailable, runtime.GOOS, err)
	}
	return store, nil
}

func validateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("name cannot be empty")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("name %q contains unsupported characters", name)
		}
	}
	return nil
}

func safeOutput(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
