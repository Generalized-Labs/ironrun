//go:build !windows

package daemon

import "os"

func currentUID() int { return os.Getuid() }
