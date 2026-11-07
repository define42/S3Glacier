package archive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestTryRemoveTempsUsesOnlyScannedNames(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "original", []byte("committed payload"))
	tarBefore, checkpointBefore := storeTestBytes(t, path), storeTestBytes(t, CommitPath(path))
	names := []string{writeCheckpointTemp(t, path, "first"), writeCheckpointTemp(t, path, "second")}
	unseen := writeCheckpointTemp(t, path, "created-after-scan")
	otherPath := filepath.Join(filepath.Dir(path), "0001.tar")
	other := writeCheckpointTemp(t, otherPath, "unrelated")
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, names); err != nil || !cleaned {
		t.Fatalf("scavenge: cleaned=%v err=%v", cleaned, err)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("scanned temporary file still exists: %q: %v", name, err)
		}
	}
	for _, name := range []string{unseen, other} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); err != nil {
			t.Fatalf("unscanned temporary file was removed: %q: %v", name, err)
		}
	}
	if !bytes.Equal(tarBefore, storeTestBytes(t, path)) || !bytes.Equal(checkpointBefore, storeTestBytes(t, CommitPath(path))) {
		t.Fatal("scavenging changed committed storage")
	}
}

func TestTryRemoveTempsRejectsNamesOutsideArchive(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"../victim", "0000.commit", ".0001.tar.commit-other", ".0000.tar.commit-", "/tmp/.0000.tar.commit-absolute"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			storeTestAppend(t, store, path, "original", []byte("good data"))
			valid := writeCheckpointTemp(t, path, "valid")
			if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{valid, name}); cleaned || !errors.Is(err, ErrCorrupt) {
				t.Fatalf("accepted an unrelated name: cleaned=%v err=%v", cleaned, err)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), valid)); err != nil {
				t.Fatal("removed files before validating the whole batch", err)
			}
			storeTestObjects(t, store, path) // Invalid caller input must not quarantine good data.
		})
	}
}

func TestTryRemoveTempsSkipsReader(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "original", []byte("reader holds shared lock"))
	name := writeCheckpointTemp(t, path, "stale")
	reader, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{name}); err != nil || cleaned {
		t.Fatalf("scavenging bypassed reader lock: cleaned=%v err=%v", cleaned, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); err != nil {
		t.Fatal("busy archive's temporary file was removed", err)
	}
	reader.Close()
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{name}); err != nil || !cleaned {
		t.Fatalf("scavenging after reader close: cleaned=%v err=%v", cleaned, err)
	}
}

func TestTryRemoveTempsSkipsActivePublication(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "original", []byte("previous commit"))
	paused, resume := make(chan struct{}), make(chan struct{})
	done := make(chan struct{})
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(func() {
		release()
		<-done
	})
	store.hook = func(stage string) error {
		if stage == "checkpoint.written" {
			close(paused)
			<-resume
		}
		return nil
	}
	finished := make(chan error, 1)
	pending := []byte("current publication must survive scavenging")
	go func() {
		defer close(done)
		_, err := store.Append(t.Context(), path, storeTestHeader("pending", pending), pending, sha256.Sum256(pending))
		finished <- err
	}()
	awaitLockSignal(t, paused)
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+filepath.Base(path)+".commit-") {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 1 {
		t.Fatalf("expected one pending checkpoint, found %v", names)
	}
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, names); err != nil || cleaned {
		t.Fatalf("scavenging bypassed active writer: cleaned=%v err=%v", cleaned, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), names[0])); err != nil {
		t.Fatal("active checkpoint was removed", err)
	}
	release()
	if err := storeTestAwaitError(t, finished); err != nil {
		t.Fatalf("publication failed after cleanup attempted: %v", err)
	}
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, names); err != nil || !cleaned {
		t.Fatalf("stale scan after publication: cleaned=%v err=%v", cleaned, err)
	}
	if objects := storeTestObjects(t, NewStore(), path); !bytes.Equal(objects["pending"], pending) {
		t.Fatal("stale scan damaged the published checkpoint")
	}
}

func TestAppendAndRecoveryLeaveTempsForPeriodicCleanup(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"new", "healthy", "interrupted append"} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			if state != "new" {
				storeTestAppend(t, store, path, "original", []byte("existing committed content"))
				if state == "interrupted append" {
					storeTestDamageFooter(t, path, storeTestCheckpoint(t, path), true)
				}
			}
			name := writeCheckpointTemp(t, path, "interrupted")
			storeTestAppend(t, store, path, "new", []byte("new committed content"))
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); err != nil {
				t.Fatalf("append scanned and removed stale temporary files: %v", err)
			}
			objects := storeTestObjects(t, store, path)
			if string(objects["new"]) != "new committed content" || state != "new" && string(objects["original"]) != "existing committed content" {
				t.Fatal("stale temporary checkpoint affected commit or recovery")
			}
			if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{name}); err != nil || !cleaned {
				t.Fatalf("periodic scavenging: cleaned=%v err=%v", cleaned, err)
			}
		})
	}
}

func TestTryRemoveTempsSyncsPartialRemovalAndPreservesQuarantine(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	storeTestAppend(t, store, path, "original", []byte("committed data"))
	names := []string{writeCheckpointTemp(t, path, "first"), writeCheckpointTemp(t, path, "second")}
	synced := false
	store.hook = func(stage string) error {
		if stage == "temps.unlinked" {
			return syscall.EIO
		}
		if stage == "temps.synced" {
			synced = true
		}
		return nil
	}
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, names); cleaned || !errors.Is(err, ErrUnavailable) || !synced {
		t.Fatalf("partial removal did not sync before failure: cleaned=%v synced=%v err=%v", cleaned, synced, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), names[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("first temporary file was not removed", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), names[1])); err != nil {
		t.Fatal("removal continued after its failure", err)
	}
	store.hook = nil
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, names); err != nil || !cleaned {
		t.Fatalf("retry failed: cleaned=%v err=%v", cleaned, err)
	}
	if reader, err := store.Open(t.Context(), path); !errors.Is(err, ErrUnavailable) || reader != nil {
		if reader != nil {
			reader.Close()
		}
		t.Fatalf("temporary cleanup cleared archive quarantine: %v", err)
	}
}

func TestTryRemoveTempsRetriesDirectorySyncAfterNamesDisappear(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	name := writeCheckpointTemp(t, path, "orphan")
	attempts := 0
	store.hook = func(stage string) error {
		if stage == "temps.before-dir-sync" {
			attempts++
			return syscall.EIO
		}
		return nil
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{name}); cleaned || !errors.Is(err, ErrUnavailable) || attempts != attempt {
			t.Fatalf("attempt %d skipped durability confirmation: cleaned=%v calls=%d err=%v", attempt, cleaned, attempts, err)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("temporary file was not unlinked", err)
		}
	}
	store.hook = nil
	if cleaned, err := store.TryRemoveTemps(t.Context(), path, []string{name}); err != nil || !cleaned {
		t.Fatalf("confirmed retry: cleaned=%v err=%v", cleaned, err)
	}
}

func TestTryRemoveTempsMissingParentDoesNotCreateFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "missing", "archive.tar")
	if cleaned, err := NewStore().TryRemoveTemps(t.Context(), path, []string{".archive.tar.commit-stale"}); err != nil || !cleaned {
		t.Fatalf("missing temporary file: cleaned=%v err=%v", cleaned, err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("scavenging created directories: entries=%v err=%v", entries, err)
	}
}

func writeCheckpointTemp(t *testing.T, path, suffix string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	name := "." + filepath.Base(path) + ".commit-" + suffix
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), name), []byte("unpublished checkpoint"), 0600); err != nil {
		t.Fatal(err)
	}
	return name
}
