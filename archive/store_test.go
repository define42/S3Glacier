package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStoreAppendRoundTripAndRepeatedNames(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	for index, size := range []int{0, 1, 511, 512, 513, 65537} {
		name := fmt.Sprintf("object-%d", size)
		data := bytes.Repeat([]byte{'x'}, size)
		header := storeTestHeader(name, data)
		header.Uname = strings.Repeat("long-owner-", 12)
		header.PAXRecords = map[string]string{"example.note": strings.Repeat("metadata-", 100)}
		created, err := store.Append(t.Context(), path, header, data, sha256.Sum256(data))
		if err != nil || !created {
			t.Fatalf("append size %d: created=%v err=%v", size, created, err)
		}
		if _, changed := header.PAXRecords[SHA256Key]; changed {
			t.Fatal("Append changed the caller's PAX records")
		}
		created, err = store.Append(t.Context(), path, header, data, sha256.Sum256(data))
		if err != nil || !created {
			t.Fatalf("identical retry: created=%v err=%v", created, err)
		}
		changed := []byte("different contents")
		storeTestAppend(t, store, path, name, changed)
		entries := storeTestEntries(t, NewStore(), path)
		if len(entries) != (index+1)*3 {
			t.Fatalf("entry count=%d, want %d including repeated names", len(entries), (index+1)*3)
		}
		for offset, want := range [][]byte{data, data, changed} {
			entry := entries[index*3+offset]
			if entry.name != name || !bytes.Equal(entry.data, want) {
				t.Fatalf("repeated entry %d: name=%q bytes=%d", offset, entry.name, len(entry.data))
			}
		}
		objects := storeTestObjects(t, NewStore(), path)
		if got, ok := objects[name]; !ok || !bytes.Equal(got, data) {
			t.Fatalf("first entry changed for size %d: present=%v got %d bytes", size, ok, len(got))
		}
	}
}

func TestStoreRepairsSameSizeFooterDamage(t *testing.T) {
	t.Parallel()
	path := storeTestPath(t)
	storeTestAppend(t, NewStore(), path, "acknowledged", []byte("durable object"))
	c := storeTestCheckpoint(t, path)
	before := storeTestBytes(t, path)
	storeTestDamageFooter(t, path, c, false)
	if got := len(storeTestBytes(t, path)); got != len(before) {
		t.Fatalf("fixture changed archive size: got %d want %d", got, len(before))
	}
	objects := storeTestObjects(t, NewStore(), path)
	if string(objects["acknowledged"]) != "durable object" {
		t.Fatalf("recovered objects=%v", objects)
	}
	after := storeTestBytes(t, path)
	if !bytes.Equal(after, before) {
		t.Fatal("same-size footer repair changed previously committed bytes")
	}
}

func TestStoreRejectsCorruptMetadataAndShortArchives(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"missing checkpoint", "invalid json", "checksum", "generation", "short archive", "split entry", "missing last digest", "malformed last digest"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			storeTestAppend(t, NewStore(), path, "acknowledged", bytes.Repeat([]byte{'a'}, 1025))
			c := storeTestCheckpoint(t, path)
			switch change {
			case "missing checkpoint":
				if err := os.Remove(CommitPath(path)); err != nil {
					t.Fatal(err)
				}
			case "invalid json":
				if err := os.WriteFile(CommitPath(path), []byte(`{"version":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				c.Checksum = strings.Repeat("0", 64)
				storeTestWriteCheckpoint(t, path, c, false)
			case "generation":
				c.Generation = strings.Repeat("0", 32)
				storeTestWriteCheckpoint(t, path, c, true)
			case "short archive":
				if err := os.Truncate(path, c.DataEnd-1); err != nil {
					t.Fatal(err)
				}
			case "split entry":
				c.DataEnd -= blockSize
				storeTestWriteCheckpoint(t, path, c, true)
			case "missing last digest", "malformed last digest":
				contents := storeTestBytes(t, path)
				entry := contents[c.LastStart:c.DataEnd]
				at := bytes.Index(entry, []byte(SHA256Key+"="))
				if at < 0 {
					t.Fatal("fixture did not contain a PAX checksum")
				}
				if change == "missing last digest" {
					copy(entry[at:], strings.Repeat("X", len(SHA256Key)))
				} else {
					copy(entry[at+len(SHA256Key)+1:], strings.Repeat("z", 64))
				}
				if err := os.WriteFile(path, contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := storeTestBytes(t, path)
			store := NewStore()
			if reader, err := store.Open(t.Context(), path); !errors.Is(err, ErrCorrupt) {
				if reader != nil {
					reader.Close()
				}
				t.Fatalf("Open corrupt archive: %v", err)
			}
			data := []byte("must not be committed")
			if _, err := store.Append(t.Context(), path, storeTestHeader("new", data), data, sha256.Sum256(data)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Append corrupt archive: %v", err)
			}
			if !bytes.Equal(before, storeTestBytes(t, path)) {
				t.Fatal("failed validation changed the archive")
			}
		})
	}
}

func TestStoreInvalidHeadersPreserveHealthyArchive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		header     *tar.Header
		data       []byte
		mayBeValid bool
	}{
		{name: "nul name", header: &tar.Header{Name: "bad\x00name", Size: 1}, data: []byte{'x'}},
		{name: "nul owner", header: &tar.Header{Name: "bad-owner", Uname: "bad\x00owner", Size: 1}, data: []byte{'x'}},
		{name: "directory-like regular alias", header: &tar.Header{Name: "directory/", Typeflag: tar.TypeRegA}, mayBeValid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			storeTestAppend(t, store, path, "acknowledged", []byte("keep this object"))
			tarBefore, checkpointBefore := storeTestBytes(t, path), storeTestBytes(t, CommitPath(path))
			created, err := store.Append(t.Context(), path, tt.header, tt.data, sha256.Sum256(tt.data))
			if errors.Is(err, ErrInvalidEntry) {
				if created || !bytes.Equal(tarBefore, storeTestBytes(t, path)) || !bytes.Equal(checkpointBefore, storeTestBytes(t, CommitPath(path))) {
					t.Fatal("invalid metadata changed the committed archive or checkpoint")
				}
			} else if err != nil || !created || !tt.mayBeValid {
				t.Fatalf("invalid-header handling: created=%v err=%v", created, err)
			} else {
				reader, err := store.Open(t.Context(), path)
				if err != nil {
					t.Fatalf("Append acknowledged an unreadable archive: %v", err)
				}
				defer reader.Close()
				tr := tar.NewReader(reader)
				found := false
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					if h.Name == tt.header.Name {
						found = true
						if h.Typeflag != tar.TypeReg {
							t.Fatalf("regular alias became nonregular TAR entry %q", h.Typeflag)
						}
					}
				}
				if !found {
					t.Fatal("acknowledged regular entry is absent")
				}
				reader.Close()
			}
			if objects := storeTestObjects(t, store, path); string(objects["acknowledged"]) != "keep this object" {
				t.Fatal("invalid metadata damaged or quarantined a good object")
			}
			storeTestAppend(t, store, path, "after", []byte("store remains healthy"))
		})
	}
}

func TestStoreCreatingCheckpointCannotResetExistingData(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"different generation", "same generation with committed objects"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			if change == "different generation" {
				// Build a healthy manifest-only TAR so the generation guard is
				// tested independently of the guard against discarding objects.
				release := acquireTestLock(t, &store.locks, path, true)
				_, err := store.prepare(path)
				release()
				if err != nil {
					t.Fatal(err)
				}
				storeTestObjects(t, store, path)
			} else {
				storeTestAppend(t, store, path, "acknowledged", []byte("cannot reset this generation"))
			}
			c := storeTestCheckpoint(t, path)
			c.State, c.DataEnd, c.LastStart = "creating", 0, 0
			if change == "different generation" {
				first := byte('0')
				if c.Generation[0] == first {
					first = '1'
				}
				c.Generation = string(first) + c.Generation[1:]
			}
			storeTestWriteCheckpoint(t, path, c, true)
			tarBefore, checkpointBefore := storeTestBytes(t, path), storeTestBytes(t, CommitPath(path))
			validation := NewStore()
			if reader, err := validation.Open(t.Context(), path); !errors.Is(err, ErrCorrupt) {
				if reader != nil {
					reader.Close()
				}
				t.Fatalf("creating checkpoint reset existing archive: %v", err)
			}
			data := []byte("must not be appended")
			if _, err := validation.Append(t.Context(), path, storeTestHeader("new", data), data, sha256.Sum256(data)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Append accepted invalid creating checkpoint: %v", err)
			}
			if !bytes.Equal(tarBefore, storeTestBytes(t, path)) || !bytes.Equal(checkpointBefore, storeTestBytes(t, CommitPath(path))) {
				t.Fatal("creating-state validation changed existing files")
			}
		})
	}
}

func TestStoreQuarantineAndDurableDeletion(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "acknowledged", []byte("old generation"))
	original := storeTestCheckpoint(t, path)
	failed := false
	store.hook = func(stage string) error {
		if stage == "tar.payload" && !failed {
			failed = true
			return syscall.ENOSPC
		}
		return nil
	}
	data := bytes.Repeat([]byte{'p'}, 100000)
	if _, err := store.Append(t.Context(), path, storeTestHeader("pending", data), data, sha256.Sum256(data)); !errors.Is(err, ErrUnavailable) || !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("ENOSPC append: %v", err)
	}
	if reader, err := store.Open(t.Context(), path); !errors.Is(err, ErrUnavailable) {
		if reader != nil {
			reader.Close()
		}
		t.Fatalf("quarantined Open: %v", err)
	}
	if removed, err := store.TryDelete(t.Context(), path); err != nil || !removed {
		t.Fatalf("delete quarantined archive: removed=%v err=%v", removed, err)
	}
	storeTestAppend(t, store, path, "fresh", []byte("new generation"))
	if current := storeTestCheckpoint(t, path); current.Generation == original.Generation {
		t.Fatal("recreation reused the deleted archive's generation")
	}
	objects := storeTestObjects(t, store, path)
	if len(objects) != 1 || string(objects["fresh"]) != "new generation" {
		t.Fatalf("recreated archive retained old objects: %v", objects)
	}
}

func TestStoreDeletionRetriesConfirmAbsentMetadata(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"delete", "reap orphan"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			storeTestAppend(t, store, path, "old", []byte("old generation"))
			remove := store.TryDelete
			if operation == "reap orphan" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				remove = store.TryReapOrphan
			}
			confirmations := 0
			store.hook = func(stage string) error {
				if stage == "delete.metadata-removed" {
					confirmations++
					return syscall.EIO
				}
				return nil
			}
			for attempt := 1; attempt <= 2; attempt++ {
				if _, err := remove(t.Context(), path); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("removal attempt %d: %v", attempt, err)
				}
				if confirmations != attempt {
					t.Fatalf("absent metadata bypassed confirmation: calls=%d attempts=%d", confirmations, attempt)
				}
				for _, name := range []string{path, CommitPath(path)} {
					if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("confirmation ran before removing %q: %v", name, err)
					}
				}
				data := []byte("must remain quarantined")
				if _, err := store.Append(t.Context(), path, storeTestHeader("blocked", data), data, sha256.Sum256(data)); !errors.Is(err, ErrUnavailable) {
					t.Fatalf("removal attempt %d cleared quarantine: %v", attempt, err)
				}
			}
			store.hook = nil
			if _, err := remove(t.Context(), path); err != nil {
				t.Fatalf("confirmed removal retry: %v", err)
			}
			storeTestAppend(t, store, path, "fresh", []byte("fresh generation"))
			if objects := storeTestObjects(t, store, path); len(objects) != 1 || string(objects["fresh"]) != "fresh generation" {
				t.Fatalf("confirmed retry did not permit a fresh archive: %v", objects)
			}
		})
	}
}

func TestStoreRemovalWithMissingParentDoesNotCreateFiles(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"delete", "reap orphan"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			root := t.TempDir()
			path := filepath.Join(root, "missing", "archive.tar")
			remove := store.TryDelete
			if operation == "reap orphan" {
				remove = store.TryReapOrphan
			}
			if _, err := remove(t.Context(), path); err != nil {
				t.Fatalf("remove missing archive: %v", err)
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatalf("removal created missing directories: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestStoreCheckpointRenameFailureDoesNotRollBackData(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "acknowledged", []byte("previous commit"))
	original := storeTestCheckpoint(t, path)
	store.hook = func(stage string) error {
		if stage == "checkpoint.renamed" {
			return syscall.EIO
		}
		return nil
	}
	data := []byte("new checkpoint already names these bytes")
	if _, err := store.Append(t.Context(), path, storeTestHeader("uncertain", data), data, sha256.Sum256(data)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failure after checkpoint rename: %v", err)
	}
	if current := storeTestCheckpoint(t, path); current.DataEnd <= original.DataEnd {
		t.Fatal("failure after rename rolled back the published checkpoint")
	}
	restarted := NewStore()
	objects := storeTestObjects(t, restarted, path)
	if len(objects) != 2 || !bytes.Equal(objects["uncertain"], data) {
		t.Fatalf("surviving checkpoint lost its data: %v", objects)
	}
	storeTestAppend(t, restarted, path, "uncertain", data)
	entries := storeTestEntries(t, restarted, path)
	if len(entries) != 3 || entries[0].name != "acknowledged" || entries[1].name != "uncertain" || entries[2].name != "uncertain" || !bytes.Equal(entries[1].data, data) || !bytes.Equal(entries[2].data, data) {
		t.Fatal("lost-response retry did not append a second copy after the original entries")
	}
}

func TestStoreReadConfirmsCheckpointDurability(t *testing.T) {
	t.Parallel()
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%v", fail), func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			data := []byte("an existing ready checkpoint")
			storeTestAppend(t, NewStore(), path, "acknowledged", data)
			tarBefore, checkpointBefore := storeTestBytes(t, path), storeTestBytes(t, CommitPath(path))
			store := NewStore()
			beforeSync, confirmed := false, false
			store.hook = func(stage string) error {
				if stage == "checkpoint.confirm-before-sync" {
					beforeSync = true
					if fail {
						return syscall.EIO
					}
				} else if stage == "checkpoint.confirmed" {
					confirmed = true
				}
				return nil
			}
			reader, err := store.Open(t.Context(), path)
			if !fail && reader == nil {
				t.Fatalf("confirmed checkpoint returned no Reader: %v", err)
			}
			if reader != nil {
				reader.Close()
				if !confirmed {
					t.Fatal("Reader was exposed before confirming checkpoint directory durability")
				}
			}
			if !beforeSync {
				t.Fatal("ready checkpoint bypassed the confirmation barrier")
			}
			if fail {
				if !errors.Is(err, ErrUnavailable) || confirmed {
					t.Fatalf("failed confirmation: err=%v confirmed=%v", err, confirmed)
				}
				if reader, err := store.Open(t.Context(), path); !errors.Is(err, ErrUnavailable) || reader != nil {
					if reader != nil {
						reader.Close()
					}
					t.Fatalf("failed confirmation did not quarantine the path: %v", err)
				}
			} else if err != nil || !confirmed {
				t.Fatalf("checkpoint confirmation: err=%v confirmed=%v", err, confirmed)
			}
			if !bytes.Equal(tarBefore, storeTestBytes(t, path)) || !bytes.Equal(checkpointBefore, storeTestBytes(t, CommitPath(path))) {
				t.Fatal("confirmation modified the existing TAR or checkpoint")
			}
		})
	}
}

func TestStoreRepeatedNameRequiresDurableCommit(t *testing.T) {
	t.Parallel()
	for _, failureStage := range []string{"", "tar.before-sync", "checkpoint.before-dir-sync"} {
		t.Run("failure="+failureStage, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			data := []byte("identical content on every attempt")
			storeTestAppend(t, NewStore(), path, "repeated", data)
			before := storeTestBytes(t, path)
			original := storeTestCheckpoint(t, path)
			store := NewStore()
			committed := false
			store.hook = func(stage string) error {
				if stage == failureStage {
					return syscall.EIO
				}
				if stage == "checkpoint.committed" {
					committed = true
				}
				return nil
			}
			created, err := store.Append(t.Context(), path, storeTestHeader("repeated", data), data, sha256.Sum256(data))
			if failureStage == "" {
				if err != nil || !created || !committed {
					t.Fatalf("repeated append did not commit: created=%v committed=%v err=%v", created, committed, err)
				}
			} else {
				if !errors.Is(err, ErrUnavailable) || created || committed {
					t.Fatalf("failed repeated append was acknowledged: created=%v committed=%v err=%v", created, committed, err)
				}
				if reader, err := store.Open(t.Context(), path); !errors.Is(err, ErrUnavailable) || reader != nil {
					if reader != nil {
						reader.Close()
					}
					t.Fatalf("failed repeated append did not quarantine archive: %v", err)
				}
			}
			restarted := NewStore()
			entries := storeTestEntries(t, restarted, path)
			want := 2
			if failureStage == "tar.before-sync" {
				want = 1
			}
			if len(entries) != want {
				t.Fatalf("recovered entry count=%d, want %d", len(entries), want)
			}
			for _, entry := range entries {
				if entry.name != "repeated" || !bytes.Equal(entry.data, data) {
					t.Fatal("repeated append damaged an entry")
				}
			}
			if !bytes.Equal(before[:original.DataEnd], storeTestBytes(t, path)[:original.DataEnd]) {
				t.Fatal("repeated append rewrote the original committed prefix")
			}
		})
	}
}

func TestStoreDeleteAndWaitingWriterSharePathIdentity(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "old", []byte("deleted object"))
	paused, resume := make(chan struct{}), make(chan struct{})
	var resumeOnce sync.Once
	t.Cleanup(func() { resumeOnce.Do(func() { close(resume) }) })
	store.hook = func(stage string) error {
		if stage == "delete.unlinked" {
			close(paused)
			<-resume
		}
		return nil
	}
	deletion := make(chan error, 1)
	go func() {
		removed, err := store.TryDelete(t.Context(), path)
		if err == nil && !removed {
			err = errors.New("archive was not deleted")
		}
		deletion <- err
	}()
	awaitLockSignal(t, paused)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	observed := &lockObservedContext{Context: ctx, queued: make(chan struct{})}
	writer := make(chan error, 1)
	go func() {
		data := []byte("fresh object")
		_, err := store.Append(observed, path, storeTestHeader("fresh", data), data, sha256.Sum256(data))
		writer <- err
	}()
	awaitLockSignal(t, observed.queued)
	if reader, err := store.TryOpen(t.Context(), path); !errors.Is(err, ErrBusy) {
		if reader != nil {
			reader.Close()
		}
		t.Fatalf("TryOpen bypassed cleanup/waiter lock: %v", err)
	}
	resumeOnce.Do(func() { close(resume) })
	if err := storeTestAwaitError(t, deletion); err != nil {
		t.Fatal(err)
	}
	if err := storeTestAwaitError(t, writer); err != nil {
		t.Fatal(err)
	}
	objects := storeTestObjects(t, store, path)
	if len(objects) != 1 || string(objects["fresh"]) != "fresh object" {
		t.Fatalf("post-deletion writer used an old generation: %v", objects)
	}
	if reaped, err := store.TryReapOrphan(t.Context(), path); err != nil || reaped {
		t.Fatalf("stale orphan scan touched a recreated archive: reaped=%v err=%v", reaped, err)
	}
}

func TestStoreBusyReaderAndIndependentPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := NewStore()
	busy := filepath.Join(root, "buckets", "four-shards", "2026", "11", "07", "10", "0000.tar")
	storeTestAppend(t, store, busy, "busy", []byte("reader held"))
	reader, err := store.Open(t.Context(), busy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	if removed, err := store.TryDelete(t.Context(), busy); err != nil || removed {
		t.Fatalf("cleanup removed an archive with a reader: removed=%v err=%v", removed, err)
	}
	paths := []string{
		filepath.Join(root, "buckets", "two-fifty-six-shards", "2026", "11", "07", "10", "0000.tar"),
		filepath.Join(root, "buckets", "four-shards", "2026", "11", "07", "11", "0000.tar"),
	}
	for _, path := range paths {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		data := []byte("independent archive")
		_, err := store.Append(ctx, path, storeTestHeader("other", data), data, sha256.Sum256(data))
		cancel()
		if err != nil {
			t.Fatalf("independent path blocked or failed: %v", err)
		}
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Reader.Close is not idempotent: %v", err)
	}
}

func TestStoreMissingReadDoesNotCreateFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "missing", "archive.tar")
	for _, open := range []func(context.Context, string) (*Reader, error){NewStore().Open, NewStore().TryOpen} {
		if reader, err := open(t.Context(), path); !errors.Is(err, os.ErrNotExist) || reader != nil {
			t.Fatalf("missing read: reader=%v err=%v", reader, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing read created directories: entries=%v err=%v", entries, err)
	}
}

func storeTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "buckets", "testing", "2026", "11", "07", "12", "0000.tar")
}

func storeTestHeader(name string, data []byte) *tar.Header {
	return &tar.Header{Name: name, Size: int64(len(data)), Mode: 0600, Format: tar.FormatPAX}
}

func storeTestAppend(t *testing.T, store *Store, path, name string, data []byte) {
	t.Helper()
	created, err := store.Append(t.Context(), path, storeTestHeader(name, data), data, sha256.Sum256(data))
	if err != nil || !created {
		t.Fatalf("append %s: created=%v err=%v", name, created, err)
	}
}

func storeTestObjects(t *testing.T, store *Store, path string) map[string][]byte {
	t.Helper()
	objects := make(map[string][]byte)
	for _, entry := range storeTestEntries(t, store, path) {
		if _, exists := objects[entry.name]; !exists {
			objects[entry.name] = entry.data
		}
	}
	return objects
}

type storeTestEntry struct {
	name string
	data []byte
}

func storeTestEntries(t *testing.T, store *Store, path string) []storeTestEntry {
	t.Helper()
	reader, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var entries []storeTestEntry
	tr := tar.NewReader(reader)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatalf("read recovered TAR: %v", err)
		}
		if IsInternalEntry(h) {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, storeTestEntry{name: h.Name, data: data})
	}
}

func storeTestBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func storeTestCheckpoint(t *testing.T, path string) checkpoint {
	t.Helper()
	c, err := readCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func storeTestWriteCheckpoint(t *testing.T, path string, c checkpoint, updateChecksum bool) {
	t.Helper()
	if updateChecksum {
		c.Checksum = c.sum()
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(CommitPath(path), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func storeTestDamageFooter(t *testing.T, path string, c checkpoint, extraTail bool) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(bytes.Repeat([]byte{0xff}, footerSize), c.DataEnd); err != nil {
		t.Fatal(err)
	}
	if extraTail {
		if err := f.Truncate(c.DataEnd + footerSize + blockSize); err != nil {
			t.Fatal(err)
		}
	}
}

func storeTestAwaitError(t *testing.T, result <-chan error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatal("archive operation did not finish")
		return ctx.Err()
	}
}
