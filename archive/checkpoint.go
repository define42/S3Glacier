package archive

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	blockSize     = 512
	footerSize    = 2 * blockSize
	formatVersion = 1
	// ManifestName identifies the internal first entry binding a TAR to its checkpoint.
	ManifestName = ".s3glacier-manifest.json"
	// SHA256Key records the original, uncompressed object's digest in its PAX header.
	SHA256Key = "S3Glacier.sha256"
)

type checkpoint struct {
	Version    int    `json:"version"`
	Generation string `json:"generation"`
	State      string `json:"state"`
	DataEnd    int64  `json:"data_end"`
	LastStart  int64  `json:"last_start"`
	Checksum   string `json:"checksum"`
}

type manifest struct {
	Version    int    `json:"version"`
	Generation string `json:"generation"`
}

func (c checkpoint) sum() string {
	c.Checksum = ""
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CommitPath returns the checkpoint next to a TAR file.
func CommitPath(path string) string { return strings.TrimSuffix(path, ".tar") + ".commit" }

// MetadataArchive maps a checkpoint or interrupted checkpoint temporary file to
// its TAR path. Cleanup can discover these even when creation never made a TAR.
func MetadataArchive(path string) (string, bool) {
	name := filepath.Base(path)
	if stem, ok := strings.CutSuffix(name, ".commit"); ok {
		return filepath.Join(filepath.Dir(path), stem+".tar"), true
	}
	if stem, ok := strings.CutPrefix(name, "."); ok {
		archive, suffix, ok := strings.Cut(stem, ".tar.commit-")
		if ok && archive != "" && suffix != "" {
			return filepath.Join(filepath.Dir(path), archive+".tar"), true
		}
	}
	return "", false
}

// IsInternalEntry identifies the archive identity record, which is not a user object.
func IsInternalEntry(h *tar.Header) bool { return h != nil && h.Name == ManifestName }

func readCheckpoint(path string) (checkpoint, error) {
	var c checkpoint
	info, err := os.Lstat(CommitPath(path))
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return c, fmt.Errorf("%w: invalid checkpoint file", ErrCorrupt)
	}
	data, err := os.ReadFile(CommitPath(path))
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: checkpoint json: %v", ErrCorrupt, err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("%w: trailing checkpoint data", ErrCorrupt)
	}
	gen, err := hex.DecodeString(c.Generation)
	if c.Version != formatVersion || err != nil || len(gen) != 16 || c.Checksum != c.sum() {
		return c, fmt.Errorf("%w: invalid checkpoint identity or checksum", ErrCorrupt)
	}
	if c.State == "creating" && c.DataEnd == 0 && c.LastStart == 0 {
		return c, nil
	}
	if c.State != "ready" || c.DataEnd < footerSize || c.DataEnd%blockSize != 0 || c.DataEnd > int64(^uint64(0)>>1)-footerSize {
		return c, fmt.Errorf("%w: invalid committed boundary", ErrCorrupt)
	}
	if c.LastStart < 0 || c.LastStart >= c.DataEnd || c.LastStart%blockSize != 0 {
		return c, fmt.Errorf("%w: invalid last entry boundary", ErrCorrupt)
	}
	return c, nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// A process can die after renaming a synced checkpoint but before syncing its
// directory. A new process may see that cached rename, so establish durability
// before exposing the archive to a reader.
func (s *Store) confirmCheckpoint(path string) error {
	if err := s.step("checkpoint.confirm-before-sync"); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return s.step("checkpoint.confirmed")
}

// An earlier removal may be visible in cache even though its directory sync
// failed or was interrupted. Confirm absence even when every unlink is a no-op.
func (s *Store) confirmDeletion(path string) error {
	if err := s.step("delete.metadata-removed"); err != nil {
		return err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Directory creation is infrequent. Sync the complete chain so a newly created
// hour cannot disappear even when several new ancestors were created together.
func (s *Store) durableDirectories(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := s.step("directories.created"); err != nil {
		return err
	}
	for {
		if err := s.step("directories.before-sync"); err != nil {
			return err
		}
		if err := syncDirectory(path); err != nil {
			return err
		}
		if err := s.step("directories.synced"); err != nil {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return s.step("directories.durable")
		}
		path = parent
	}
}

func (s *Store) publish(path string, c checkpoint) (err error) {
	c.Checksum = c.sum()
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".commit-*")
	if err != nil {
		return err
	}
	name := f.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	if err = s.step("checkpoint.before-write"); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = s.step("checkpoint.written"); err != nil {
		return err
	}
	if err = s.step("checkpoint.before-sync"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = s.step("checkpoint.synced"); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = s.step("checkpoint.before-rename"); err != nil {
		return err
	}
	if err = os.Rename(name, CommitPath(path)); err != nil {
		return err
	}
	if err = s.step("checkpoint.renamed"); err != nil {
		return err
	}
	if err = s.step("checkpoint.before-dir-sync"); err != nil {
		return err
	}
	if err = syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return s.step("checkpoint.committed")
}

func regularFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: archive is not a regular file", ErrCorrupt)
	}
	return info, nil
}

func validateManifest(f *os.File, c checkpoint) error {
	tr := tar.NewReader(io.NewSectionReader(f, 0, footerSize))
	h, err := tr.Next()
	if err != nil || !IsInternalEntry(h) || h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > blockSize {
		return fmt.Errorf("%w: invalid archive manifest", ErrCorrupt)
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return fmt.Errorf("%w: read manifest: %v", ErrCorrupt, err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil || m.Version != c.Version || m.Generation != c.Generation {
		return fmt.Errorf("%w: checkpoint belongs to a different archive", ErrCorrupt)
	}
	return nil
}

// Validate the physical boundary using the last entry's actual PAX/header
// length and payload padding. This does not scan earlier payloads on every GET.
func validateBoundary(f *os.File, c checkpoint) error {
	r := io.NewSectionReader(f, c.LastStart, c.DataEnd-c.LastStart)
	h, err := tar.NewReader(r).Next()
	if err != nil || h.Typeflag != tar.TypeReg {
		return fmt.Errorf("%w: invalid committed entry header", ErrCorrupt)
	}
	position, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	available := c.DataEnd - c.LastStart - position
	if h.Size < 0 || h.Size > available || available-h.Size != (-h.Size)&(blockSize-1) {
		return fmt.Errorf("%w: committed boundary splits a tar entry", ErrCorrupt)
	}
	if c.LastStart == 0 && !IsInternalEntry(h) || c.LastStart != 0 && IsInternalEntry(h) {
		return fmt.Errorf("%w: invalid committed entry identity", ErrCorrupt)
	}
	if c.LastStart != 0 {
		digest, err := hex.DecodeString(h.PAXRecords[SHA256Key])
		if err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("%w: missing object checksum", ErrCorrupt)
		}
	}
	return nil
}

func inspect(f *os.File, c checkpoint) error {
	if c.State != "ready" {
		return errRecovery
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < c.DataEnd {
		return fmt.Errorf("%w: archive is shorter than its committed prefix", ErrCorrupt)
	}
	if err := validateManifest(f, c); err != nil {
		return err
	}
	if err := validateBoundary(f, c); err != nil {
		return err
	}
	if info.Size() != c.DataEnd+footerSize {
		return errRecovery
	}
	var tail [footerSize]byte
	if _, err := f.ReadAt(tail[:], c.DataEnd); err != nil {
		return err
	}
	if tail != footer {
		return errRecovery
	}
	return nil
}

func (s *Store) initialize(path string, c checkpoint) (checkpoint, error) {
	// Only a durably published creating record authorizes truncating a partial
	// initial file. No object can have been acknowledged in this generation yet.
	if err := validateCreating(path, c); err != nil {
		return c, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return c, s.quarantine(path, err)
	}
	data, err := json.Marshal(manifest{Version: formatVersion, Generation: c.Generation})
	if err != nil {
		return c, errors.Join(err, f.Close())
	}
	tw := tar.NewWriter(f)
	h := &tar.Header{Name: ManifestName, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(data)), Format: tar.FormatUSTAR}
	if err = tw.WriteHeader(h); err == nil {
		_, err = tw.Write(data)
	}
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = s.step("create.written")
	}
	if err == nil {
		err = s.step("create.before-sync")
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = syncDirectory(filepath.Dir(path))
	}
	if err == nil {
		err = s.step("create.synced")
	}
	if err != nil {
		return c, s.quarantine(path, err)
	}
	c.State, c.DataEnd = "ready", footerSize
	if err := s.publish(path, c); err != nil {
		return c, s.quarantine(path, err)
	}
	if err := removeTemps(path); err != nil {
		return c, s.quarantine(path, err)
	}
	return c, nil
}

func validateCreating(path string, c checkpoint) error {
	info, err := regularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Initialization writes only a two-block manifest and a two-block footer.
	// Anything larger can contain committed objects from a mismatched snapshot.
	if info.Size() > 2*footerSize {
		return fmt.Errorf("%w: creating checkpoint paired with populated archive", ErrCorrupt)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	h, err := tr.Next()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, tar.ErrHeader) {
			return nil
		}
		return err
	}
	if !IsInternalEntry(h) || h.Typeflag != tar.TypeReg || h.Size < 1 || h.Size > blockSize {
		return fmt.Errorf("%w: creating checkpoint paired with unrelated archive", ErrCorrupt)
	}
	data, err := io.ReadAll(tr)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	var m manifest
	if json.Unmarshal(data, &m) == nil && (m.Version != c.Version || m.Generation != c.Generation) {
		return fmt.Errorf("%w: creating checkpoint belongs to a different archive", ErrCorrupt)
	}
	return nil
}

func (s *Store) prepare(path string) (checkpoint, error) {
	if _, err := regularFile(path); err == nil {
		return s.recover(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return checkpoint{}, err
	}
	// A missing TAR is absent, even if cleanup crashed before removing its
	// checkpoint. Reset that orphan durably before creating a new generation.
	if err := s.durableDirectories(filepath.Dir(path)); err != nil {
		return checkpoint{}, s.quarantine(path, err)
	}
	if err := removeCheckpoint(path); err != nil {
		return checkpoint{}, s.quarantine(path, err)
	}
	if err := removeTemps(path); err != nil {
		return checkpoint{}, s.quarantine(path, err)
	}
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return checkpoint{}, err
	}
	c := checkpoint{Version: formatVersion, Generation: hex.EncodeToString(generation[:]), State: "creating"}
	if err := s.publish(path, c); err != nil {
		return c, s.quarantine(path, err)
	}
	return s.initialize(path, c)
}

func removeCheckpoint(path string) error {
	if err := os.Remove(CommitPath(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func removeTemps(path string) error {
	entries, err := os.ReadDir(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := "." + filepath.Base(path) + ".commit-"
	removed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(filepath.Dir(path), entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed = true
	}
	if removed {
		return syncDirectory(filepath.Dir(path))
	}
	return nil
}
