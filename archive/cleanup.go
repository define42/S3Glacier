package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TryRemoveTemps removes the checkpoint temporary basenames collected for path
// by a directory scan. It never enumerates the directory itself. A nonblocking
// exclusive archive lock prevents scavenging an active checkpoint publication;
// busy readers or writers return false without removing anything. Names must
// belong to this archive and cannot contain path components. Success follows a
// directory sync, including on retries where the names are already absent.
// Removing temporary files does not clear an archive's existing quarantine.
func (s *Store) TryRemoveTemps(ctx context.Context, path string, names []string) (bool, error) {
	path, err := canonical(path)
	if err != nil {
		return false, err
	}
	prefix := "." + filepath.Base(path) + ".commit-"
	for _, name := range names {
		if name != filepath.Base(name) || !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
			return false, fmt.Errorf("%w: temporary file does not belong to archive", ErrCorrupt)
		}
	}
	if len(names) == 0 {
		return true, nil
	}
	release, err := s.locks.acquire(ctx, path, true, true)
	if errors.Is(err, ErrBusy) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer release()
	if err := checkParents(path); err != nil {
		return false, err
	}

	var removeErr error
	for _, name := range names {
		temporary := filepath.Join(filepath.Dir(path), name)
		if _, err := regularFile(temporary); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			removeErr = err
			break
		}
		if err := os.Remove(temporary); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			removeErr = err
			break
		}
		if err := s.step("temps.unlinked"); err != nil {
			removeErr = err
			break
		}
	}
	// Persist successful unlinks even when a later removal failed. Repeating a
	// scan may find only absent names after an earlier failed directory sync.
	syncErr := s.step("temps.before-dir-sync")
	if syncErr == nil {
		syncErr = syncDirectory(filepath.Dir(path))
		if errors.Is(syncErr, os.ErrNotExist) {
			syncErr = nil
		}
	}
	if syncErr == nil {
		syncErr = s.step("temps.synced")
	}
	if err := errors.Join(removeErr, syncErr); err != nil {
		return false, s.quarantine(path, err)
	}
	return true, nil
}
