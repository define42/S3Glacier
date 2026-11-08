package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Reader holds a shared archive lock until Close. The file is recovered before
// it is exposed, so reads and raw TAR exports see only a committed archive.
type Reader struct {
	file     *os.File
	commit   checkpoint
	release  func()
	once     sync.Once
	closeErr error
}

// Read reads committed TAR bytes.
func (r *Reader) Read(p []byte) (int, error) { return r.file.Read(p) }

// ReadAt reads committed TAR bytes at off.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) { return r.file.ReadAt(p, off) }

// Seek positions the reader within the committed TAR.
func (r *Reader) Seek(off int64, whence int) (int64, error) { return r.file.Seek(off, whence) }

// Stat describes the recovered TAR.
func (r *Reader) Stat() (os.FileInfo, error) { return r.file.Stat() }

// Name returns the canonical archive path.
func (r *Reader) Name() string { return r.file.Name() }

// Close closes the file before releasing its shared lock. It is idempotent.
func (r *Reader) Close() error {
	r.once.Do(func() { r.closeErr = r.file.Close(); r.release() })
	return r.closeErr
}

// Open waits for a shared lock, recovering a dirty archive exclusively first.
// Missing TARs return os.ErrNotExist without creating files or directories.
func (s *Store) Open(ctx context.Context, path string) (*Reader, error) {
	return s.open(ctx, path, false)
}

// TryOpen is Open without waiting for a contended lock; it returns ErrBusy.
func (s *Store) TryOpen(ctx context.Context, path string) (*Reader, error) {
	return s.open(ctx, path, true)
}

func (s *Store) open(ctx context.Context, path string, try bool) (*Reader, error) {
	path, err := canonical(path)
	if err != nil {
		return nil, err
	}
	for {
		release, err := s.locks.acquire(ctx, path, false, try)
		if err != nil {
			return nil, err
		}
		f, c, err := s.openChecked(path)
		if err == nil {
			return &Reader{file: f, commit: c, release: release}, nil
		}
		release()
		if !errors.Is(err, errRecovery) {
			return nil, err
		}
		release, err = s.locks.acquire(ctx, path, true, try)
		if err != nil {
			return nil, err
		}
		_, err = s.recover(path)
		release()
		if err != nil {
			return nil, err
		}
	}
}

func (s *Store) openChecked(path string) (*os.File, checkpoint, error) {
	var c checkpoint
	if err := checkParents(path); err != nil {
		return nil, c, err
	}
	if err := s.healthy(path); err != nil {
		return nil, c, err
	}
	if _, err := regularFile(path); err != nil {
		return nil, c, err
	}
	c, err := readCheckpoint(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, c, fmt.Errorf("%w: existing archive has no checkpoint", ErrCorrupt)
	}
	if err != nil {
		return nil, c, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, c, err
	}
	if err := inspect(f, c); err != nil {
		return nil, c, errors.Join(err, f.Close())
	}
	if err := s.confirmCheckpoint(path); err != nil {
		return nil, c, s.quarantine(path, errors.Join(err, f.Close()))
	}
	return f, c, nil
}

// recover is called only under the exclusive lock. It never adopts uncommitted
// entries and never extends missing committed bytes with zeroes. Unpublished
// checkpoint temporaries are left for periodic cleanup; recovering a healthy
// archive must not enumerate all sibling shards on every append.
func (s *Store) recover(path string) (checkpoint, error) {
	var c checkpoint
	if err := checkParents(path); err != nil {
		return c, err
	}
	if err := s.healthy(path); err != nil {
		return c, err
	}
	if _, err := regularFile(path); err != nil {
		return c, err
	}
	c, err := readCheckpoint(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, fmt.Errorf("%w: existing archive has no checkpoint", ErrCorrupt)
	}
	if err != nil {
		return c, err
	}
	if c.State == "creating" {
		return s.initialize(path, c)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return c, err
	}
	err = inspect(f, c)
	if err == nil {
		if err := f.Close(); err != nil {
			return c, s.quarantine(path, err)
		}
		return c, nil
	}
	if !errors.Is(err, errRecovery) {
		return c, errors.Join(err, f.Close())
	}
	// The manifest and committed size were checked by inspect before errRecovery.
	if _, err = f.WriteAt(footer[:], c.DataEnd); err == nil {
		err = s.step("recovery.footer")
	}
	if err == nil {
		err = f.Truncate(c.DataEnd + footerSize)
	}
	if err == nil {
		err = s.step("recovery.truncated")
	}
	if err == nil {
		err = s.step("recovery.before-sync")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.step("recovery.synced")
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return c, s.quarantine(path, err)
	}
	return c, nil
}
