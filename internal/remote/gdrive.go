package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

var (
	ErrNotImplemented = errors.New("gdrive sync is not fully implemented yet")
	ErrNotFound       = errors.New("remote file not found")
)

type GDriveRemote struct {
	srv *drive.Service
}

// NewGDriveRemote creates a Google Drive remote sync backend using application default credentials.
func NewGDriveRemote(ctx context.Context) (*GDriveRemote, error) {
	srv, err := drive.NewService(ctx, option.WithScopes(drive.DriveFileScope))
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Drive client: %v", err)
	}
	return &GDriveRemote{srv: srv}, nil
}

func (g *GDriveRemote) Name() string {
	return "gdrive"
}

// findFileID finds a file by name in the root directory.
func (g *GDriveRemote) findFileID(name string) (string, error) {
	q := fmt.Sprintf("name='%s' and trashed=false", name)
	r, err := g.srv.Files.List().Q(q).Spaces("drive").PageSize(1).Fields("files(id, name)").Do()
	if err != nil {
		return "", fmt.Errorf("unable to search files: %v", err)
	}
	if len(r.Files) == 0 {
		return "", ErrNotFound
	}
	return r.Files[0].Id, nil
}

func (g *GDriveRemote) Push(ctx context.Context, name string, data io.Reader) error {
	fileID, err := g.findFileID(name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	if errors.Is(err, ErrNotFound) {
		// Create new file
		f := &drive.File{Name: name}
		_, err = g.srv.Files.Create(f).Media(data).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("create file: %v", err)
		}
		return nil
	}

	// Update existing file
	_, err = g.srv.Files.Update(fileID, nil).Media(data).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("update file: %v", err)
	}
	return nil
}

func (g *GDriveRemote) Pull(ctx context.Context, name string) (io.ReadCloser, error) {
	fileID, err := g.findFileID(name)
	if err != nil {
		return nil, err
	}
	res, err := g.srv.Files.Get(fileID).Context(ctx).Download()
	if err != nil {
		return nil, fmt.Errorf("download file: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("bad status code: %d", res.StatusCode)
	}
	return res.Body, nil
}
