package archive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrBusy means a nonblocking archive lock could not be acquired.
	ErrBusy = errors.New("archive is busy")
	// ErrConflict means an object name already contains different content.
	ErrConflict = errors.New("object already exists with different content")
	// ErrInvalidEntry means caller-supplied metadata cannot form a regular TAR entry.
	ErrInvalidEntry = errors.New("invalid archive entry")
	// ErrCorrupt means the archive and its checkpoint cannot be safely reconciled.
	ErrCorrupt = errors.New("archive or checkpoint is corrupt")
	// ErrUnavailable means a storage failure quarantined the archive for this process.
	ErrUnavailable = errors.New("archive is unavailable after a storage failure")
	errRecovery    = errors.New("archive requires recovery")
	footer         [footerSize]byte
	// Default coordinates all archive users in the standalone server.
	Default = NewStore()
)

// Store shares locks between readers, writers, and cleanup. NewStore must not be
// used to bypass another live Store's locks for the same data directory.
// A storage failure quarantines the affected path until durable eviction or a
// process restart after the underlying storage and its durable state have been
// repaired. Restarting alone cannot repair an actual I/O or sync failure.
// Opening an archive validates its checkpoint and footer again.
type Store struct {
	locks  lockRegistry
	mu     sync.Mutex
	failed map[string]error
	hook   func(string) error // Tests inject failures or terminate a subprocess at persistence boundaries.
}

// NewStore constructs an independent archive coordinator. Serving code uses Default.
func NewStore() *Store { return &Store{failed: make(map[string]error)} }

func canonical(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if filepath.Ext(path) != ".tar" {
		return "", fmt.Errorf("%w: expected a tar path", ErrCorrupt)
	}
	return filepath.Clean(path), nil
}

// Check after locking, before opening or repairing any file. Reject aliases so
// two different lock keys cannot address the same archive through a symlink.
func checkParents(path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && !info.IsDir() {
			return fmt.Errorf("%w: archive parent is not a real directory", ErrCorrupt)
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

func (s *Store) clearFailure(path string) {
	s.mu.Lock()
	delete(s.failed, path)
	s.mu.Unlock()
}

func (s *Store) healthy(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failed[path]; err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

func (s *Store) quarantine(path string, err error) error {
	if err == nil {
		return nil
	}
	s.mu.Lock()
	if s.failed == nil {
		s.failed = make(map[string]error)
	}
	s.failed[path] = err
	s.mu.Unlock()
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func (s *Store) step(stage string) error {
	if s.hook != nil {
		return s.hook(stage)
	}
	return nil
}

func findObject(ctx context.Context, f *os.File, c checkpoint, name, digest string) (bool, error) {
	section := io.NewSectionReader(f, 0, c.DataEnd)
	tr := tar.NewReader(section)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			position, seekErr := section.Seek(0, io.SeekCurrent)
			if seekErr != nil {
				return false, seekErr
			}
			if position != c.DataEnd {
				return false, fmt.Errorf("%w: premature end of committed archive", ErrCorrupt)
			}
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("%w: read committed entry: %v", ErrCorrupt, err)
		}
		if IsInternalEntry(h) {
			continue
		}
		storedDigest, digestErr := hex.DecodeString(h.PAXRecords[SHA256Key])
		if h.Typeflag != tar.TypeReg || digestErr != nil || len(storedDigest) != sha256.Size {
			return false, fmt.Errorf("%w: invalid committed object metadata", ErrCorrupt)
		}
		if h.Name == name {
			if h.PAXRecords[SHA256Key] == digest {
				return true, nil
			}
			return false, ErrConflict
		}
	}
}

// Append commits a complete stored payload. digest describes the original,
// uncompressed bytes. Identical name/digest retries return false without writing;
// different bytes return ErrConflict. Successful new entries return true only
// after the TAR and checkpoint have been synced. Cancellation controls lock wait
// and duplicate lookup; once writing starts, the commit is completed or quarantined.
func (s *Store) Append(ctx context.Context, path string, header *tar.Header, data []byte, digest [32]byte) (bool, error) {
	path, err := canonical(path)
	if err != nil {
		return false, err
	}
	if header == nil || header.Name == "" || strings.HasSuffix(header.Name, "/") || IsInternalEntry(header) || header.Size != int64(len(data)) {
		return false, ErrInvalidEntry
	}
	if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
		return false, ErrInvalidEntry
	}
	digestString := hex.EncodeToString(digest[:])
	h := *header
	h.Typeflag = tar.TypeReg
	h.Format = tar.FormatPAX
	h.PAXRecords = maps.Clone(header.PAXRecords)
	if h.PAXRecords == nil {
		h.PAXRecords = make(map[string]string)
	}
	h.PAXRecords[SHA256Key] = digestString
	// Invalid client metadata must never quarantine existing good data. Encode
	// the prepared header before opening an archive or replacing its footer.
	if err := tar.NewWriter(io.Discard).WriteHeader(&h); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidEntry, err)
	}
	release, err := s.locks.acquire(ctx, path, true, false)
	if err != nil {
		return false, err
	}
	defer release()
	if err := checkParents(path); err != nil {
		return false, err
	}
	if err := s.healthy(path); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c, err := s.prepare(path)
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	exists, err := findObject(ctx, f, c, header.Name, digestString)
	if err != nil {
		return false, errors.Join(err, f.Close())
	}
	if exists {
		if err := f.Close(); err != nil {
			return false, s.quarantine(path, err)
		}
		if err := s.confirmCheckpoint(path); err != nil {
			return false, s.quarantine(path, err)
		}
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(err, f.Close())
	}
	if _, err := f.Seek(c.DataEnd, io.SeekStart); err != nil {
		return false, errors.Join(err, f.Close())
	}
	tw := tar.NewWriter(f)
	if err = tw.WriteHeader(&h); err == nil {
		err = s.step("tar.header")
	}
	for offset := 0; err == nil && offset < len(data); {
		end := min(offset+32*1024, len(data))
		_, err = tw.Write(data[offset:end])
		offset = end
		if err == nil {
			err = s.step("tar.payload")
		}
	}
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = s.step("tar.footer")
	}
	var position int64
	if err == nil {
		position, err = f.Seek(0, io.SeekCurrent)
	}
	if err == nil {
		err = f.Truncate(position)
	}
	if err == nil {
		err = s.step("tar.before-sync")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.step("tar.synced")
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return false, s.quarantine(path, err)
	}
	c.LastStart, c.DataEnd = c.DataEnd, position-footerSize
	if err := s.publish(path, c); err != nil {
		return false, s.quarantine(path, err)
	}
	return true, nil
}

// TryDelete evicts an archive without waiting for readers or writers and without
// allocating a deletion marker. It syncs the TAR unlink before removing its
// checkpoint. Orphan checkpoints are reaped without recreating their TAR.
// The in-memory lock remains shared with any waiters across path recreation.
func (s *Store) TryDelete(ctx context.Context, path string) (bool, error) {
	path, err := canonical(path)
	if err != nil {
		return false, err
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
	removed := false
	if _, err := regularFile(path); err == nil {
		if err := os.Remove(path); err != nil {
			return false, s.quarantine(path, err)
		}
		removed = true
		if err := s.step("delete.unlinked"); err != nil {
			return true, s.quarantine(path, err)
		}
		if err := s.step("delete.before-dir-sync"); err != nil {
			return true, s.quarantine(path, err)
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return true, s.quarantine(path, err)
		}
		if err := s.step("delete.synced"); err != nil {
			return true, s.quarantine(path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := removeCheckpoint(path); err != nil {
		return removed, s.quarantine(path, err)
	}
	if err := removeTemps(path); err != nil {
		return removed, s.quarantine(path, err)
	}
	if err := s.confirmDeletion(path); err != nil {
		return removed, s.quarantine(path, err)
	}
	if err := s.step("delete.committed"); err != nil {
		return removed, s.quarantine(path, err)
	}
	s.clearFailure(path)
	return removed, nil
}

// TryReapOrphan removes a checkpoint only if its TAR is still absent under the
// exclusive lock. Cleanup may call this even without disk pressure: a stale
// directory scan can never make it delete a newly recreated archive.
func (s *Store) TryReapOrphan(ctx context.Context, path string) (bool, error) {
	path, err := canonical(path)
	if err != nil {
		return false, err
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
	if _, err := os.Lstat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if _, err := os.Lstat(CommitPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := removeCheckpoint(path); err != nil {
		return false, s.quarantine(path, err)
	}
	if err := removeTemps(path); err != nil {
		return false, s.quarantine(path, err)
	}
	if err := s.confirmDeletion(path); err != nil {
		return false, s.quarantine(path, err)
	}
	s.clearFailure(path)
	return true, nil
}
