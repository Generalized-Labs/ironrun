//go:build windows

package daemon

import (
	"context"
)

func SocketPath() (string, error) { return "", ErrUnsupported }
func Serve(context.Context) error { return ErrUnsupported }
func Ping(context.Context) error  { return ErrUnsupported }
