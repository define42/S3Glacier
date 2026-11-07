package archive

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDirectoryFailurePreventsArchivePublication(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"directories.created", "directories.before-sync", "directories.synced", "directories.durable"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			path := storeTestPath(t)
			store := NewStore()
			injected, published := false, false
			store.hook = func(current string) error {
				if strings.HasPrefix(current, "checkpoint.") {
					published = true
				}
				if current == stage {
					injected = true
					return syscall.EIO
				}
				return nil
			}
			payload := []byte("must wait for durable directories")
			committed, err := store.Append(t.Context(), path, storeTestHeader("event", payload), payload, sha256.Sum256(payload))
			if !injected || committed || !errors.Is(err, ErrUnavailable) || !errors.Is(err, syscall.EIO) {
				t.Fatalf("directory failure: injected=%v committed=%v err=%v", injected, committed, err)
			}
			if published {
				t.Fatal("checkpoint publication started before directory persistence succeeded")
			}
			for _, name := range []string{path, CommitPath(path)} {
				if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("archive state created after directory failure: %s: %v", name, err)
				}
			}
			if _, err := os.Stat(filepath.Dir(path)); err != nil {
				t.Fatalf("fixture should leave visible directories for retry: %v", err)
			}
			if _, err := store.Open(t.Context(), path); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("failed archive was not quarantined: %v", err)
			}

			// Simulated failure is removed. A fresh process must sync the visible
			// directory chain again rather than assume its existence is durable.
			restarted := NewStore()
			durable, syncs := false, 0
			restarted.hook = func(current string) error {
				if current == "directories.synced" {
					syncs++
				}
				if current == "directories.durable" {
					durable = true
				}
				if current == "checkpoint.before-write" && !durable {
					t.Error("restart published before confirming the directory chain")
				}
				return nil
			}
			storeTestAppend(t, restarted, path, "event", payload)
			if !durable || syncs < 2 {
				t.Fatalf("restart did not sync directory and ancestors: durable=%v syncs=%d", durable, syncs)
			}
			if got := storeTestObjects(t, NewStore(), path)["event"]; string(got) != string(payload) {
				t.Fatalf("committed event after restart = %q", got)
			}
		})
	}
}
