package archive

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Injected errors exercise acknowledgement and recovery decisions. They do not
// emulate a power cut or claim that restarting repairs a real filesystem EIO.
func TestAppendFailureNeverAcknowledgesUnconfirmedCommit(t *testing.T) {
	t.Parallel()
	stages := []struct {
		name      string
		published bool
	}{
		{name: "tar.footer"},
		{name: "tar.before-sync"},
		{name: "tar.synced"},
		{name: "checkpoint.before-write"},
		{name: "checkpoint.written"},
		{name: "checkpoint.before-sync"},
		{name: "checkpoint.synced"},
		{name: "checkpoint.before-rename"},
		{name: "checkpoint.renamed", published: true},
		{name: "checkpoint.before-dir-sync", published: true},
		{name: "checkpoint.committed", published: true},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			t.Parallel()
			store := NewStore()
			path := storeTestPath(t)
			originalData := []byte("previously acknowledged and durable")
			storeTestAppend(t, store, path, "original", originalData)
			original := storeTestCheckpoint(t, path)
			before := storeTestBytes(t, path)
			failed := false
			store.hook = func(current string) error {
				if current == stage.name {
					failed = true
					return syscall.EIO
				}
				return nil
			}

			pending := bytes.Repeat([]byte("new payload"), 6000)
			created, err := store.Append(t.Context(), path, storeTestHeader("pending", pending), pending, sha256.Sum256(pending))
			if !failed || created || !errors.Is(err, ErrUnavailable) || !errors.Is(err, syscall.EIO) {
				t.Fatalf("failed commit acknowledged or bypassed failure: failed=%v created=%v err=%v", failed, created, err)
			}
			afterFailure := storeTestBytes(t, path)
			if len(afterFailure) < int(original.DataEnd) || !bytes.Equal(before[:original.DataEnd], afterFailure[:original.DataEnd]) {
				t.Fatal("failed append changed the previously committed prefix")
			}
			reader, err := store.Open(t.Context(), path)
			if reader != nil {
				reader.Close()
			}
			if reader != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("failed archive was exposed before recovery: reader=%v err=%v", reader, err)
			}
			if created, err := store.Append(t.Context(), path, storeTestHeader("blocked", pending), pending, sha256.Sum256(pending)); created || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("quarantine allowed another append: created=%v err=%v", created, err)
			}
			if !bytes.Equal(afterFailure, storeTestBytes(t, path)) {
				t.Fatal("quarantined append modified the archive")
			}

			entries := storeTestEntries(t, NewStore(), path)
			want := 1
			if stage.published {
				want = 2
			}
			if len(entries) != want || entries[0].name != "original" || !bytes.Equal(entries[0].data, originalData) {
				t.Fatalf("recovery lost the original entry or exposed an uncommitted entry: count=%d want=%d", len(entries), want)
			}
			if stage.published && (entries[1].name != "pending" || !bytes.Equal(entries[1].data, pending)) {
				t.Fatal("recovery lost the entry named by the surviving checkpoint")
			}
			afterRecovery := storeTestBytes(t, path)
			if !bytes.Equal(before[:original.DataEnd], afterRecovery[:original.DataEnd]) {
				t.Fatal("recovery changed the previously committed prefix")
			}
			if !stage.published && !bytes.Equal(before, afterRecovery) {
				t.Fatal("recovery did not restore the original TAR after an unpublished append")
			}
		})
	}
}

func TestAppendWaitsForCheckpointDirectorySync(t *testing.T) {
	t.Parallel()
	store := NewStore()
	path := storeTestPath(t)
	original := []byte("first durable object")
	storeTestAppend(t, store, path, "original", original)
	beforeSync, allowSync, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(allowSync) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Append did not exit after releasing the sync barrier")
		}
	})
	store.hook = func(stage string) error {
		if stage == "checkpoint.before-dir-sync" {
			close(beforeSync)
			<-allowSync
		}
		return nil
	}
	type appendResult struct {
		created bool
		err     error
	}
	finished := make(chan appendResult, 1)
	pending := []byte("success must wait for directory durability")
	go func() {
		defer close(done)
		created, err := store.Append(t.Context(), path, storeTestHeader("pending", pending), pending, sha256.Sum256(pending))
		finished <- appendResult{created: created, err: err}
	}()
	awaitLockSignal(t, beforeSync)
	select {
	case result := <-finished:
		t.Fatalf("Append returned before checkpoint directory sync: created=%v err=%v", result.created, result.err)
	default:
	}
	reader, err := store.TryOpen(t.Context(), path)
	if reader != nil {
		reader.Close()
	}
	if reader != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("reader bypassed an unconfirmed commit: reader=%v err=%v", reader, err)
	}
	release()
	select {
	case result := <-finished:
		if !result.created || result.err != nil {
			t.Fatalf("durable commit did not succeed: created=%v err=%v", result.created, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Append did not finish after allowing the directory sync")
	}
	entries := storeTestEntries(t, NewStore(), path)
	if len(entries) != 2 || entries[0].name != "original" || !bytes.Equal(entries[0].data, original) || entries[1].name != "pending" || !bytes.Equal(entries[1].data, pending) {
		t.Fatal("successful commit was not readable through a fresh coordinator")
	}
}
