package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestListMetadataCacheRefreshAndLogicalKeys(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	for _, name := range []string{"z", "a/two", "a/one", "a/deep/file", "a", "b/z"} {
		storeTestAppend(t, s, path, name, []byte(name))
	}
	storeTestAppend(t, s, path, "a/one", []byte("later duplicate with a different size"))
	header := storeTestHeader("compressed", []byte("stored"))
	header.Mode, header.Uid = 1, 12345
	if _, err := s.Append(t.Context(), path, header, []byte("stored"), sha256.Sum256([]byte("original"))); err != nil {
		t.Fatal(err)
	}
	var scanned int
	s.hook = func(stage string) error {
		if stage == "list.header" {
			scanned++
		}
		return nil
	}
	all := []ListEntry{
		{Key: "a", Size: 1}, {Key: "a/deep/file", Size: 11}, {Key: "a/one", Size: 5},
		{Key: "a/two", Size: 5}, {Key: "b/z", Size: 3}, {Key: "compressed", Size: 12345}, {Key: "z", Size: 1},
	}
	listTestWant(t, s, path, ListOptions{Limit: 1001}, all)
	if scanned != 8 {
		t.Fatalf("cold scan visited %d objects, want 8", scanned)
	}
	for _, test := range []struct {
		name string
		opts ListOptions
		want []ListEntry
	}{
		{"prefix", ListOptions{Prefix: "a/", Limit: 10}, all[1:4]},
		{"literal prefix", ListOptions{Prefix: "A/", Limit: 10}, nil},
		{"after", ListOptions{After: "a/one", Limit: 2}, all[3:5]},
		{"delimiter", ListOptions{Delimiter: "/", Limit: 10}, []ListEntry{{Key: "a", Size: 1}, {Key: "a/", CommonPrefix: true}, {Key: "b/", CommonPrefix: true}, all[5], all[6]}},
		{"delimiter after", ListOptions{After: "a/", Delimiter: "/", Limit: 1}, []ListEntry{{Key: "b/", CommonPrefix: true}}},
		{"delimiter after child", ListOptions{After: "a/deep/a", Delimiter: "/", Limit: 1}, []ListEntry{{Key: "b/", CommonPrefix: true}}},
		{"prefix delimiter", ListOptions{Prefix: "a/", Delimiter: "/", Limit: 10}, []ListEntry{{Key: "a/deep/", CommonPrefix: true}, all[2], all[3]}},
		{"multi-byte delimiter", ListOptions{Prefix: "a", Delimiter: "/d", Limit: 10}, []ListEntry{all[0], {Key: "a/d", CommonPrefix: true}, all[2], all[3]}},
		{"zero", ListOptions{}, nil},
	} {
		t.Run(test.name, func(t *testing.T) { listTestWant(t, s, path, test.opts, test.want) })
	}
	if scanned != 8 {
		t.Fatalf("cached queries rescanned headers: got %d", scanned)
	}
	storeTestAppend(t, s, path, "a/one", []byte("another duplicate"))
	storeTestAppend(t, s, path, "a/new", []byte("new"))
	listTestWant(t, s, path, ListOptions{Prefix: "a/", Limit: 10}, []ListEntry{all[1], {Key: "a/new", Size: 3}, all[2], all[3]})
	if scanned != 10 {
		t.Fatalf("refresh scanned %d headers, want exactly the original 8 plus 2 newly committed entries", scanned)
	}
	index := s.lists.get(path)
	if index == nil || index.dataEnd != storeTestCheckpoint(t, path).DataEnd {
		t.Fatal("cache did not advance its committed boundary")
	}
}

func TestListRecoversUncommittedTailBeforeUsingCache(t *testing.T) {
	t.Parallel()
	for _, warm := range []bool{false, true} {
		t.Run(fmt.Sprintf("warm=%t", warm), func(t *testing.T) {
			t.Parallel()
			s, path := NewStore(), storeTestPath(t)
			storeTestAppend(t, s, path, "committed", []byte("safe"))
			want := []ListEntry{{Key: "committed", Size: 4}}
			if warm {
				listTestWant(t, s, path, ListOptions{Limit: 10}, want)
			}
			before := storeTestBytes(t, path)
			c := storeTestCheckpoint(t, path)
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(c.DataEnd, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			writer := tar.NewWriter(f)
			if err := writer.WriteHeader(storeTestHeader("uncommitted", []byte("hidden"))); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("hidden")); err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(writer.Close(), f.Close()); err != nil {
				t.Fatal(err)
			}
			listTestWant(t, s, path, ListOptions{Limit: 10}, want)
			if !bytes.Equal(storeTestBytes(t, path), before) {
				t.Fatal("listing did not restore the exact committed TAR and footer")
			}
		})
	}
}

func TestListSnapshotAllowsAppendAndRejectsRecreation(t *testing.T) {
	t.Parallel()
	for _, recreate := range []bool{false, true} {
		t.Run(fmt.Sprintf("recreate=%t", recreate), func(t *testing.T) {
			t.Parallel()
			s, path := NewStore(), storeTestPath(t)
			storeTestAppend(t, s, path, "old", []byte("first"))
			paused, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once, releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(resume) }) }
			s.hook = func(stage string) error {
				if stage == "list.scan" {
					once.Do(func() { close(paused); <-resume })
				}
				return nil
			}
			var entries []ListEntry
			var listErr error
			go func() {
				defer close(done)
				entries, listErr = s.List(t.Context(), path, ListOptions{Limit: 10})
			}()
			t.Cleanup(func() { release(); <-done })
			awaitLockSignal(t, paused)
			// A snapshot scan must hold neither a reader nor a writer lock.
			unlock, err := s.locks.acquire(t.Context(), path, true, true)
			if err != nil {
				t.Fatalf("listing held the archive lock during its scan: %v", err)
			}
			unlock()
			if recreate {
				if removed, err := s.TryDelete(t.Context(), path); err != nil || !removed {
					t.Fatalf("delete during scan: removed=%v err=%v", removed, err)
				}
			}
			storeTestAppend(t, s, path, "new", []byte("second"))
			release()
			awaitLockSignal(t, done)
			if recreate {
				if !errors.Is(listErr, os.ErrNotExist) || len(entries) != 0 || s.lists.get(path) != nil {
					t.Fatalf("obsolete generation escaped: entries=%v err=%v", entries, listErr)
				}
				listTestWant(t, s, path, ListOptions{Limit: 10}, []ListEntry{{Key: "new", Size: 6}})
			} else {
				if listErr != nil || !slices.Equal(entries, []ListEntry{{Key: "old", Size: 5}}) {
					t.Fatalf("snapshot chased a concurrent append: entries=%v err=%v", entries, listErr)
				}
				listTestWant(t, s, path, ListOptions{Limit: 10}, []ListEntry{{Key: "new", Size: 6}, {Key: "old", Size: 5}})
			}
		})
	}
}

func TestListWarmCacheStillConfirmsCheckpointAndQuarantinesFailure(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	storeTestAppend(t, s, path, "old", []byte("safe"))
	listTestWant(t, s, path, ListOptions{Limit: 1}, []ListEntry{{Key: "old", Size: 4}})
	s.hook = func(stage string) error {
		if stage == "checkpoint.confirm-before-sync" {
			return syscall.EIO
		}
		return nil
	}
	if entries, err := s.List(t.Context(), path, ListOptions{Limit: 1}); !errors.Is(err, ErrUnavailable) || len(entries) != 0 {
		t.Fatalf("warm cache bypassed checkpoint confirmation: entries=%v err=%v", entries, err)
	}
	if s.lists.get(path) != nil {
		t.Fatal("quarantined archive retained cached metadata")
	}
	s.hook = nil
	if _, err := s.List(t.Context(), path, ListOptions{Limit: 1}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("quarantine bypassed: %v", err)
	}
	listTestWant(t, NewStore(), path, ListOptions{Limit: 1}, []ListEntry{{Key: "old", Size: 4}})
}

func TestListInvalidatesShrunkMissingAndCorruptArchives(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	storeTestAppend(t, s, path, "first", []byte("old"))
	original, checkpoint := storeTestBytes(t, path), storeTestCheckpoint(t, path)
	storeTestAppend(t, s, path, "second", []byte("new"))
	listTestWant(t, s, path, ListOptions{Limit: 10}, []ListEntry{{Key: "first", Size: 3}, {Key: "second", Size: 3}})
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	storeTestWriteCheckpoint(t, path, checkpoint, true)
	listTestWant(t, s, path, ListOptions{Limit: 10}, []ListEntry{{Key: "first", Size: 3}})
	if err := os.WriteFile(CommitPath(path), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(t.Context(), path, ListOptions{Limit: 10}); !errors.Is(err, ErrCorrupt) || s.lists.get(path) != nil {
		t.Fatalf("corrupt archive served cached data: %v", err)
	}
	if _, err := s.TryDelete(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(t.Context(), path, ListOptions{Limit: 10}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing archive: %v", err)
	}
}

func TestListOversizedArchiveUsesBoundedCollector(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	s.lists.limit = 1024
	for i := 19; i >= 0; i-- {
		name := fmt.Sprintf("group/%02d", i)
		storeTestAppend(t, s, path, name, bytes.Repeat([]byte{'x'}, i+1))
	}
	storeTestAppend(t, s, path, "group/00", []byte("later duplicate"))
	storeTestAppend(t, s, path, "group/19", []byte("evicted duplicate"))
	for range 2 {
		listTestWant(t, s, path, ListOptions{Limit: 3}, []ListEntry{{Key: "group/00", Size: 1}, {Key: "group/01", Size: 2}, {Key: "group/02", Size: 3}})
		listTestWant(t, s, path, ListOptions{Prefix: "group/", After: "group/15", Limit: 3}, []ListEntry{{Key: "group/16", Size: 17}, {Key: "group/17", Size: 18}, {Key: "group/18", Size: 19}})
		listTestWant(t, s, path, ListOptions{Delimiter: "/", Limit: 3}, []ListEntry{{Key: "group/", CommonPrefix: true}})
	}
	index := s.lists.get(path)
	if index == nil || !index.oversized || len(index.objects) != 0 || s.lists.bytes > s.lists.limit {
		t.Fatalf("oversized archive retained an index: index=%+v bytes=%d", index, s.lists.bytes)
	}
}

func TestListCacheEvictsWithinByteBudget(t *testing.T) {
	t.Parallel()
	s := NewStore()
	s.lists.limit = 1600
	root := t.TempDir()
	paths := []string{filepath.Join(root, "first.tar"), filepath.Join(root, "second.tar"), filepath.Join(root, "third.tar")}
	for _, path := range paths {
		for i := range 4 {
			storeTestAppend(t, s, path, fmt.Sprintf("object-%d", i), []byte("body"))
		}
		if _, err := s.List(t.Context(), path, ListOptions{Limit: 10}); err != nil {
			t.Fatal(err)
		}
		if s.lists.bytes > s.lists.limit {
			t.Fatalf("cache exceeded byte budget: %d > %d", s.lists.bytes, s.lists.limit)
		}
	}
	if s.lists.get(paths[0]) != nil || s.lists.get(paths[2]) == nil {
		t.Fatal("cache did not evict the least recently used archive")
	}
	listTestWant(t, s, paths[0], ListOptions{Limit: 1}, []ListEntry{{Key: "object-0", Size: 4}})
}

func TestListBuildWaitCancellationAndWarmHit(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	storeTestAppend(t, s, path, "object", []byte("body"))
	want := []ListEntry{{Key: "object", Size: 4}}
	listTestWant(t, s, path, ListOptions{Limit: 1}, want)
	release, _, err := s.lists.acquireBuild(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	entries, err := s.List(ctx, path, ListOptions{Limit: 1})
	if err != nil || !slices.Equal(entries, want) {
		t.Fatalf("warm cache waited for an unrelated build: entries=%v err=%v", entries, err)
	}
	s.lists.remove(path)
	confirmed := make(chan struct{})
	var once sync.Once
	s.hook = func(stage string) error {
		if stage == "checkpoint.confirmed" {
			once.Do(func() { close(confirmed) })
		}
		return nil
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := s.List(ctx, path, ListOptions{Limit: 1}); finished <- err }()
	awaitLockSignal(t, confirmed)
	cancel()
	if err := storeTestAwaitError(t, finished); !errors.Is(err, context.Canceled) {
		t.Fatalf("build wait ignored cancellation: %v", err)
	}
	if removed, err := s.TryDelete(t.Context(), path); err != nil || !removed {
		t.Fatalf("canceled waiter retained archive lock: removed=%v err=%v", removed, err)
	}
}

func TestListCancelsDuringScanWithoutPublishingPartialIndex(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	storeTestAppend(t, s, path, "a", []byte("first"))
	storeTestAppend(t, s, path, "b", []byte("second"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.hook = func(stage string) error {
		if stage == "list.header" {
			cancel()
		}
		return nil
	}
	if entries, err := s.List(ctx, path, ListOptions{Limit: 1}); !errors.Is(err, context.Canceled) || len(entries) != 0 {
		t.Fatalf("scan cancellation: entries=%v err=%v", entries, err)
	}
	if s.lists.get(path) != nil {
		t.Fatal("canceled scan published partial metadata")
	}
	s.hook = nil
	listTestWant(t, s, path, ListOptions{Limit: 10}, []ListEntry{{Key: "a", Size: 5}, {Key: "b", Size: 6}})
}

func TestListConcurrentColdRequestsShareOneScan(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	storeTestAppend(t, s, path, "a", []byte("first"))
	storeTestAppend(t, s, path, "b", []byte("second"))
	var scanned atomic.Int64
	s.hook = func(stage string) error {
		if stage == "list.header" {
			scanned.Add(1)
		}
		return nil
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			entries, err := s.List(t.Context(), path, ListOptions{Limit: 1})
			if err != nil || !slices.Equal(entries, []ListEntry{{Key: "a", Size: 5}}) {
				t.Errorf("concurrent List: entries=%v err=%v", entries, err)
			}
		})
	}
	wg.Wait()
	if scanned.Load() != 2 {
		t.Fatalf("concurrent requests redundantly scanned %d headers, want 2", scanned.Load())
	}
}

func listTestWant(t *testing.T, store *Store, path string, opts ListOptions, want []ListEntry) {
	t.Helper()
	got, err := store.List(t.Context(), path, opts)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("List(%+v) = %+v, %v; want %+v", opts, got, err, want)
	}
}

func TestListIncrementalRefreshCanOutgrowCache(t *testing.T) {
	t.Parallel()
	s, path := NewStore(), storeTestPath(t)
	s.lists.limit = int64(256 + len(path) + 32 + 3*(128+len("a")))
	storeTestAppend(t, s, path, "c", []byte("first c"))
	storeTestAppend(t, s, path, "a", []byte("first a"))
	listTestWant(t, s, path, ListOptions{Limit: 2}, []ListEntry{{Key: "a", Size: 7}, {Key: "c", Size: 7}})
	if index := s.lists.get(path); index == nil || index.oversized {
		t.Fatal("initial small archive was not cached")
	}
	storeTestAppend(t, s, path, "a", []byte("later duplicate"))
	storeTestAppend(t, s, path, "b", []byte("b"))
	storeTestAppend(t, s, path, "d", []byte("d"))
	listTestWant(t, s, path, ListOptions{Limit: 3}, []ListEntry{{Key: "a", Size: 7}, {Key: "b", Size: 1}, {Key: "c", Size: 7}})
	if index := s.lists.get(path); index == nil || !index.oversized || len(index.objects) != 0 {
		t.Fatal("incremental refresh retained an oversized index")
	}
	listTestWant(t, s, path, ListOptions{Limit: 3}, []ListEntry{{Key: "a", Size: 7}, {Key: "b", Size: 1}, {Key: "c", Size: 7}})
}
