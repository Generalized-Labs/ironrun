package remote

import (
	"context"
	"io"
)

// Remote defines an interface for syncing encrypted vaults with remote backends.
type Remote interface {
	// Push uploads an encrypted vault state to the remote.
	Push(ctx context.Context, name string, data io.Reader) error
	
	// Pull downloads an encrypted vault state from the remote.
	Pull(ctx context.Context, name string) (io.ReadCloser, error)
	
	// Name returns the identifier of the remote backend (e.g. "gdrive").
	Name() string
}
