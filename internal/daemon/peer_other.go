//go:build !windows && !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

func peerUID(conn net.Conn) (int, error) { return 0, fmt.Errorf("peer credentials unsupported") }
