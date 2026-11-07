//go:build integration

package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// These subprocesses terminate at real persistence boundaries. They simulate a
// lost process, not a power cut that can roll back unsynced filesystem changes.
func TestStoreRecoversAfterProcessExitDuringAppend(t *testing.T) {
	t.Parallel()
	stages := []string{
		"tar.header", "tar.payload", "tar.footer", "tar.synced",
		"checkpoint.written", "checkpoint.synced", "checkpoint.renamed", "checkpoint.committed",
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			path := storeTestPath(t)
			storeTestAppend(t, NewStore(), path, "acknowledged", []byte("previously committed bytes"))
			before := storeTestBytes(t, path)
			original := storeTestCheckpoint(t, path)
			storeTestCrash(t, path, "append", stage)
			restarted := NewStore()
			confirmed := false
			restarted.hook = func(stage string) error {
				if stage == "checkpoint.confirmed" {
					confirmed = true
				}
				return nil
			}
			objects := storeTestObjects(t, restarted, path)
			if !confirmed {
				t.Fatal("restarted reader exposed a checkpoint without confirming directory durability")
			}
			if string(objects["acknowledged"]) != "previously committed bytes" {
				t.Fatalf("previous commit was damaged at %s", stage)
			}
			published := stage == "checkpoint.renamed" || stage == "checkpoint.committed"
			pending, exists := objects["pending"]
			if exists != published || exists && !bytes.Equal(pending, storeTestPendingPayload()) {
				t.Fatalf("pending object visibility at %s: exists=%v want=%v", stage, exists, published)
			}
			after := storeTestBytes(t, path)
			if len(after) < int(original.DataEnd) || !bytes.Equal(before[:original.DataEnd], after[:original.DataEnd]) {
				t.Fatal("recovery rewrote previously committed payload bytes")
			}
			if !published && !bytes.Equal(after, before) {
				t.Fatal("uncommitted append was not rolled back to the original TAR")
			}
			if published {
				data := storeTestPendingPayload()
				committed := false
				restarted.hook = func(stage string) error {
					if stage == "checkpoint.committed" {
						committed = true
					}
					return nil
				}
				created, err := restarted.Append(t.Context(), path, storeTestHeader("pending", data), data, sha256.Sum256(data))
				if err != nil || !created || !committed {
					t.Fatalf("lost-response retry was not durably appended: created=%v committed=%v err=%v", created, committed, err)
				}
				entries := storeTestEntries(t, restarted, path)
				if len(entries) != 3 || entries[0].name != "acknowledged" || entries[1].name != "pending" || entries[2].name != "pending" || !bytes.Equal(entries[1].data, data) || !bytes.Equal(entries[2].data, data) {
					t.Fatal("lost-response retry did not append a second copy after the existing entries")
				}
			} else {
				storeTestAppend(t, restarted, path, "after-recovery", []byte("later valid append"))
				objects = storeTestObjects(t, restarted, path)
				if len(objects) != 2 || string(objects["after-recovery"]) != "later valid append" {
					t.Fatal("recovery left the archive unusable for subsequent appends")
				}
			}
		})
	}
}

func TestStoreDuplicateAppendCrashPreservesFirstEntry(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"tar.payload", "checkpoint.renamed", "checkpoint.committed"} {
		t.Run(stage, func(t *testing.T) {
			path := storeTestPath(t)
			first := []byte("first committed content remains authoritative")
			storeTestAppend(t, NewStore(), path, "pending", first)
			before := storeTestBytes(t, path)
			original := storeTestCheckpoint(t, path)
			// The helper appends the same name with different content and exits
			// before delivering a response, possibly after publishing the commit.
			storeTestCrash(t, path, "append", stage)
			restarted := NewStore()
			entries := storeTestEntries(t, restarted, path)
			published := stage != "tar.payload"
			want := 1
			if published {
				want = 2
			}
			if len(entries) != want || entries[0].name != "pending" || !bytes.Equal(entries[0].data, first) {
				t.Fatalf("crashed duplicate changed first entry or count: entries=%d want=%d", len(entries), want)
			}
			if published && (entries[1].name != "pending" || !bytes.Equal(entries[1].data, storeTestPendingPayload())) {
				t.Fatal("published duplicate was not preserved after restart")
			}
			if !bytes.Equal(before[:original.DataEnd], storeTestBytes(t, path)[:original.DataEnd]) {
				t.Fatal("duplicate recovery rewrote the original committed prefix")
			}
			storeTestAppend(t, restarted, path, "pending", storeTestPendingPayload())
			entries = storeTestEntries(t, restarted, path)
			if len(entries) != want+1 || !bytes.Equal(entries[0].data, first) {
				t.Fatal("retry failed to append or replaced the earliest entry")
			}
			if objects := storeTestObjects(t, restarted, path); !bytes.Equal(objects["pending"], first) {
				t.Fatal("first-match lookup changed after crashed duplicate and retry")
			}
		})
	}
}

func TestStoreRecoversAfterProcessExitDuringCreation(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"checkpoint.renamed", "create.written", "create.synced"} {
		t.Run(stage, func(t *testing.T) {
			path := storeTestPath(t)
			storeTestCrash(t, path, "append", stage)
			restarted := NewStore()
			reader, err := restarted.Open(t.Context(), path)
			if reader != nil {
				reader.Close()
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("open interrupted creation: %v", err)
			}
			storeTestAppend(t, restarted, path, "fresh", []byte("first acknowledged object"))
			objects := storeTestObjects(t, restarted, path)
			if len(objects) != 1 || string(objects["fresh"]) != "first acknowledged object" {
				t.Fatalf("interrupted creation exposed an uncommitted object: %v", objects)
			}
		})
	}
}

func TestStoreRecoveryCanBeInterruptedAndRepeated(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"recovery.footer", "recovery.truncated", "recovery.synced"} {
		t.Run(stage, func(t *testing.T) {
			path := storeTestPath(t)
			storeTestAppend(t, NewStore(), path, "acknowledged", []byte("committed before repair"))
			before := storeTestBytes(t, path)
			storeTestDamageFooter(t, path, storeTestCheckpoint(t, path), true)
			storeTestCrash(t, path, "recover", stage)
			objects := storeTestObjects(t, NewStore(), path)
			if string(objects["acknowledged"]) != "committed before repair" || !bytes.Equal(before, storeTestBytes(t, path)) {
				t.Fatal("repeated recovery did not preserve the committed archive")
			}
		})
	}
}

func TestStoreDeletionCanBeInterruptedWithoutResurrection(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"delete.unlinked", "delete.synced", "delete.committed"} {
		t.Run(stage, func(t *testing.T) {
			path := storeTestPath(t)
			storeTestAppend(t, NewStore(), path, "deleted", []byte("old generation"))
			original := storeTestCheckpoint(t, path)
			storeTestCrash(t, path, "delete", stage)
			restarted := NewStore()
			if reader, err := restarted.Open(t.Context(), path); !errors.Is(err, os.ErrNotExist) || reader != nil {
				if reader != nil {
					reader.Close()
				}
				t.Fatalf("deleted archive was reconstructed: %v", err)
			}
			if _, err := restarted.TryReapOrphan(t.Context(), path); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(CommitPath(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("orphan checkpoint survived cleanup: %v", err)
			}
			storeTestAppend(t, restarted, path, "fresh", []byte("new generation"))
			if current := storeTestCheckpoint(t, path); current.Generation == original.Generation {
				t.Fatal("recreation reused the deleted generation")
			}
			objects := storeTestObjects(t, restarted, path)
			if len(objects) != 1 || string(objects["fresh"]) != "new generation" {
				t.Fatalf("deleted content was resurrected: %v", objects)
			}
		})
	}
}

func TestStoreCrashHelper(t *testing.T) {
	if os.Getenv("S3GLACIER_ARCHIVE_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	path, operation, target := os.Getenv("S3GLACIER_ARCHIVE_CRASH_PATH"), os.Getenv("S3GLACIER_ARCHIVE_CRASH_OPERATION"), os.Getenv("S3GLACIER_ARCHIVE_CRASH_STAGE")
	store := NewStore()
	store.hook = func(stage string) error {
		if stage == target {
			os.Exit(86) // Deliberately bypass file closes and all deferred recovery.
		}
		return nil
	}
	var err error
	switch operation {
	case "append":
		data := storeTestPendingPayload()
		_, err = store.Append(t.Context(), path, storeTestHeader("pending", data), data, sha256.Sum256(data))
	case "recover":
		var reader *Reader
		reader, err = store.Open(t.Context(), path)
		if reader != nil {
			reader.Close()
		}
	case "delete":
		_, err = store.TryDelete(t.Context(), path)
	default:
		t.Fatalf("unknown helper operation %q", operation)
	}
	t.Fatalf("operation %s did not terminate at stage %s: %v", operation, target, err)
}

func storeTestCrash(t *testing.T, path, operation, stage string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestStoreCrashHelper$")
	command.Env = append(os.Environ(),
		"S3GLACIER_ARCHIVE_CRASH_HELPER=1", "S3GLACIER_ARCHIVE_CRASH_PATH="+path,
		"S3GLACIER_ARCHIVE_CRASH_OPERATION="+operation, "S3GLACIER_ARCHIVE_CRASH_STAGE="+stage,
		"GORACE=atexit_sleep_ms=0",
	)
	output, err := command.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 86 {
		t.Fatalf("crash helper %s/%s: err=%v output=%s", operation, stage, err, output)
	}
}

func storeTestPendingPayload() []byte {
	return bytes.Repeat([]byte("pending payload\x00\xff"), 9000)
}
