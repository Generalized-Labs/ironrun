//go:build !darwin && !linux && !windows

package envset

import "fmt"

type nativeStore struct{}

func newNativeStore() (ValueStore, error) {
	return nil, fmt.Errorf("no supported native credential manager")
}
