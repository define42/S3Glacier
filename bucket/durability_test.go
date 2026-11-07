package bucket

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOpenConfirmsLoadedDefinitions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		syncErr error
	}{
		{name: "confirmed"},
		{name: "sync failure", syncErr: syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root, expected := durabilityFixture(t)
			metaDir := filepath.Join(root, ".buckets")
			definition := filepath.Join(metaDir, "logs.json")
			before, err := os.ReadFile(definition)
			if err != nil {
				t.Fatal(err)
			}
			var synced []string
			store, err := open(root, func(path string) error {
				synced = append(synced, path)
				if path == metaDir && tc.syncErr != nil {
					return tc.syncErr
				}
				return syncDirectory(path)
			})
			if !slices.Equal(synced, []string{root, metaDir}) {
				t.Fatalf("synced directories = %v, want root and configuration directory", synced)
			}
			if tc.syncErr != nil {
				if store != nil || !errors.Is(err, tc.syncErr) {
					t.Fatalf("failed confirmation exposed a store: store=%v err=%v", store, err)
				}
			} else {
				if err != nil || store == nil {
					t.Fatalf("confirmed reopen: store=%v err=%v", store, err)
				}
				if got := store.List(); !slices.Equal(got, expected) {
					t.Fatalf("reopen changed definitions: got=%v want=%v", got, expected)
				}
			}
			after, err := os.ReadFile(definition)
			if err != nil || string(after) != string(before) {
				t.Fatalf("confirmation changed the existing definition: err=%v", err)
			}
		})
	}
}

func TestOpenWaitsForConfigurationSync(t *testing.T) {
	t.Parallel()
	root, expected := durabilityFixture(t)
	metaDir := filepath.Join(root, ".buckets")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Open did not finish after releasing configuration sync")
		}
	})
	type result struct {
		store *Store
		err   error
	}
	finished := make(chan result, 1)
	go func() {
		defer close(done)
		store, err := open(root, func(path string) error {
			if path == metaDir {
				close(entered)
				<-release
			}
			return syncDirectory(path)
		})
		finished <- result{store: store, err: err}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("Open did not reach configuration sync")
	}
	select {
	case got := <-finished:
		t.Fatalf("Open returned before configuration sync completed: %+v", got)
	default:
	}
	unblock()
	select {
	case got := <-finished:
		if got.err != nil || got.store == nil {
			t.Fatalf("Open after configuration sync: store=%v err=%v", got.store, got.err)
		}
		if actual := got.store.List(); !slices.Equal(actual, expected) {
			t.Fatalf("loaded definitions changed: got=%v want=%v", actual, expected)
		}
	case <-ctx.Done():
		t.Fatal("Open did not finish after configuration sync")
	}
}

func durabilityFixture(t *testing.T) (string, []Bucket) {
	t.Helper()
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("logs", 4); err != nil {
		t.Fatal(err)
	}
	return root, store.List()
}
