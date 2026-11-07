package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gofrs/flock"
)

// acquireDataRoot guards the single-process ownership contract required by the
// in-memory archive registry. This one lifetime guard is not an archive lock and
// must never be unlinked while a server may be running.
func acquireDataRoot(root string) (*flock.Flock, error) {
	guard := flock.New(filepath.Join(root, ".server.lock"))
	locked, err := guard.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock data directory: %w", errors.Join(err, guard.Close()))
	}
	if !locked {
		if err := guard.Close(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("data directory %q is already owned by another server", root)
	}
	return guard, nil
}
