package envset

import "errors"

// ErrProjectIdentityChanged means the recorded metadata belongs to a different
// checkout path or Git origin. Opening that project's vault would also fail.
var ErrProjectIdentityChanged = errors.New("project identity changed")

// InspectMetadata reads project environment configuration without opening the
// vault, contacting native secure storage, or changing any files. Version-one
// metadata is interpreted in memory only; the returned entries are names and
// configuration, never secret values. A successful inspection says nothing
// about the availability or decryptability of values in the vault.
func InspectMetadata(root string) (Metadata, error) {
	meta, err := readMetadata(metadataPath(root))
	if err != nil {
		return Metadata{}, err
	}
	identity, err := DiscoverIdentity(root)
	if err != nil {
		return Metadata{}, err
	}
	if !sameIdentity(meta.Identity, identity) {
		return Metadata{}, ErrProjectIdentityChanged
	}
	migrateMetadata(&meta)
	return meta, nil
}
