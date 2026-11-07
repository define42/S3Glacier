package archive

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLockRegistryReadersAndIndependentPaths(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	root := t.TempDir()
	key := filepath.Join(root, "10", "0000.tar")
	first := acquireTestLock(t, &registry, key, false)
	second := acquireTestLock(t, &registry, root+"/10/unused/../0000.tar", false)
	assertLockState(t, &registry, key, 2, 2, false, 0)
	assertLockBusy(t, &registry, key, true)
	other := acquireTestLock(t, &registry, filepath.Join(root, "11", "0000.tar"), true)
	other()
	first()
	first() // A duplicate release must not consume another reader's reference.
	assertLockState(t, &registry, key, 1, 1, false, 0)
	second()
	assertNoLockEntries(t, &registry)
}

func TestLockRegistryCanceledContextDoesNotCreateEntry(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, try := range []bool{false, true} {
		release, err := registry.acquire(ctx, filepath.Join(t.TempDir(), "archive.tar"), true, try)
		if !errors.Is(err, context.Canceled) || release != nil {
			t.Fatalf("acquire canceled context: release=%v err=%v", release != nil, err)
		}
	}
	assertNoLockEntries(t, &registry)
}

func TestLockRegistryCancellationRemovesWaiter(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	key := filepath.Join(t.TempDir(), "archive.tar")
	holder := acquireTestLock(t, &registry, key, true)
	waiter, cancel := enqueueTestLock(t, &registry, key, false)
	assertLockState(t, &registry, key, 2, 0, true, 1)
	cancel()
	result := awaitTestLock(t, waiter)
	if !errors.Is(result.err, context.Canceled) || result.release != nil {
		t.Fatalf("canceled waiter: release=%v err=%v", result.release != nil, result.err)
	}
	assertLockState(t, &registry, key, 1, 0, true, 0)
	holder()
	assertNoLockEntries(t, &registry)
}

func TestLockRegistryWriterFairnessAndReaderBatch(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	key := filepath.Join(t.TempDir(), "archive.tar")
	initialReader := acquireTestLock(t, &registry, key, false)
	firstWriter, _ := enqueueTestLock(t, &registry, key, true)
	firstReader, _ := enqueueTestLock(t, &registry, key, false)
	secondReader, _ := enqueueTestLock(t, &registry, key, false)
	secondWriter, _ := enqueueTestLock(t, &registry, key, true)
	lastReader, _ := enqueueTestLock(t, &registry, key, false)
	assertLockState(t, &registry, key, 6, 1, false, 5)
	assertLockBusy(t, &registry, key, false) // A new reader cannot bypass a writer.
	initialReader()
	writerRelease := requireTestLock(t, awaitTestLock(t, firstWriter))
	assertLockState(t, &registry, key, 5, 0, true, 4)
	writerRelease()
	firstRelease := requireTestLock(t, awaitTestLock(t, firstReader))
	secondRelease := requireTestLock(t, awaitTestLock(t, secondReader))
	assertLockState(t, &registry, key, 4, 2, false, 2)
	firstRelease()
	assertLockState(t, &registry, key, 3, 1, false, 2)
	secondRelease()
	writerRelease = requireTestLock(t, awaitTestLock(t, secondWriter))
	assertLockState(t, &registry, key, 2, 0, true, 1)
	writerRelease()
	requireTestLock(t, awaitTestLock(t, lastReader))()
	assertNoLockEntries(t, &registry)
}

func TestLockRegistryCanceledWriterUnblocksSharedReaders(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	key := filepath.Join(t.TempDir(), "archive.tar")
	initialReader := acquireTestLock(t, &registry, key, false)
	writer, cancel := enqueueTestLock(t, &registry, key, true)
	reader, _ := enqueueTestLock(t, &registry, key, false)
	cancel()
	if result := awaitTestLock(t, writer); !errors.Is(result.err, context.Canceled) {
		t.Fatalf("canceled writer: %v", result.err)
	}
	readerRelease := requireTestLock(t, awaitTestLock(t, reader))
	assertLockState(t, &registry, key, 2, 2, false, 0)
	readerRelease()
	initialReader()
	assertNoLockEntries(t, &registry)
}

func TestLockRegistryCancellationAfterGrantReleasesSlot(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	key := filepath.Join(t.TempDir(), "archive.tar")
	holder := acquireTestLock(t, &registry, key, true)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	observed := &grantObservedContext{
		Context: ctx,
		queued:  make(chan struct{}),
		block:   make(chan struct{}),
		blocked: make(chan struct{}),
		resume:  make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-observed.resume:
		default:
			close(observed.resume)
		}
	})
	result := make(chan testLockResult, 1)
	go func() {
		release, err := registry.acquire(observed, key, true, false)
		result <- testLockResult{release: release, err: err}
	}()
	awaitLockSignal(t, observed.queued)
	close(observed.block)
	holder()
	awaitLockSignal(t, observed.blocked) // The waiter owns the grant but has not returned.
	cancel()
	close(observed.resume)
	got := awaitTestLock(t, result)
	if !errors.Is(got.err, context.Canceled) || got.release != nil {
		t.Fatalf("cancellation after grant: release=%v err=%v", got.release != nil, got.err)
	}
	assertNoLockEntries(t, &registry)
	acquireTestLock(t, &registry, key, true)()
}

func TestLockRegistryRetainsIdentityForWaitersAcrossRecreation(t *testing.T) {
	t.Parallel()
	var registry lockRegistry
	key := filepath.Join(t.TempDir(), "archive.tar")
	cleanup := acquireTestLock(t, &registry, key, true)
	original := lockEntry(t, &registry, key)
	writer, _ := enqueueTestLock(t, &registry, key, true)
	cleanup() // The archive may be deleted while this lock is held.
	writerRelease := requireTestLock(t, awaitTestLock(t, writer))
	if entry := lockEntry(t, &registry, key); entry != original {
		t.Fatal("granting a waiter replaced the archive's lock identity")
	}
	assertLockBusy(t, &registry, key, true)
	newReader, _ := enqueueTestLock(t, &registry, key, false)
	writerRelease()
	readerRelease := requireTestLock(t, awaitTestLock(t, newReader))
	if entry := lockEntry(t, &registry, key); entry != original {
		t.Fatal("a recreated archive bypassed the existing waiter's lock")
	}
	readerRelease()
	assertNoLockEntries(t, &registry)
	newHolder := acquireTestLock(t, &registry, key, true)
	if entry := lockEntry(t, &registry, key); entry == original {
		t.Fatal("idle entry was retained instead of being safely retired")
	}
	writerRelease() // A stale release cannot affect the replacement entry.
	assertLockBusy(t, &registry, key, false)
	newHolder()
	assertNoLockEntries(t, &registry)
}

type testLockResult struct {
	release func()
	err     error
}

// Observing Done establishes that acquire has queued before the test proceeds.
type lockObservedContext struct {
	context.Context
	queued chan struct{}
	once   sync.Once
}

func (c *lockObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.queued) })
	return c.Context.Done()
}

type grantObservedContext struct {
	lockObservedContext
	block   chan struct{}
	blocked chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *grantObservedContext) Err() error {
	select {
	case <-c.block:
		c.once.Do(func() { close(c.blocked) })
		<-c.resume
	default:
	}
	return c.Context.Err()
}

func acquireTestLock(t *testing.T, registry *lockRegistry, key string, write bool) func() {
	t.Helper()
	release, err := registry.acquire(t.Context(), key, write, true)
	return requireTestLock(t, testLockResult{release: release, err: err})
}

func enqueueTestLock(t *testing.T, registry *lockRegistry, key string, write bool) (<-chan testLockResult, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	observed := &lockObservedContext{Context: ctx, queued: make(chan struct{})}
	result := make(chan testLockResult, 1)
	go func() {
		release, err := registry.acquire(observed, key, write, false)
		result <- testLockResult{release: release, err: err}
	}()
	awaitLockSignal(t, observed.queued)
	return result, cancel
}

func awaitTestLock(t *testing.T, result <-chan testLockResult) testLockResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case got := <-result:
		return got
	case <-ctx.Done():
		t.Fatal("lock request did not finish")
		return testLockResult{}
	}
}

func requireTestLock(t *testing.T, result testLockResult) func() {
	t.Helper()
	if result.err != nil || result.release == nil {
		t.Fatalf("acquire lock: release=%v err=%v", result.release != nil, result.err)
	}
	t.Cleanup(result.release)
	return result.release
}

func awaitLockSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatal("lock request did not reach its synchronization point")
	}
}

func assertLockBusy(t *testing.T, registry *lockRegistry, key string, write bool) {
	t.Helper()
	release, err := registry.acquire(t.Context(), key, write, true)
	if release != nil {
		release()
	}
	if release != nil || !errors.Is(err, ErrBusy) {
		t.Fatalf("try acquire contended lock: release=%v err=%v", release != nil, err)
	}
}

func lockEntry(t *testing.T, registry *lockRegistry, key string) *pathLock {
	t.Helper()
	canonical, err := filepath.Abs(key)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry := registry.entries[canonical]
	if entry == nil {
		t.Fatal("active lock entry is missing")
	}
	return entry
}

func assertLockState(t *testing.T, registry *lockRegistry, key string, refs, readers int, writer bool, queued int) {
	t.Helper()
	canonical, err := filepath.Abs(key)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry := registry.entries[canonical]
	if entry == nil || entry.refs != refs || entry.readers != readers || entry.writer != writer || entry.waiters.Len() != queued {
		t.Fatalf("lock state=%+v; want refs=%d readers=%d writer=%v queued=%d", entry, refs, readers, writer, queued)
	}
}

func assertNoLockEntries(t *testing.T, registry *lockRegistry) {
	t.Helper()
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.entries) != 0 {
		t.Fatalf("idle lock entries were retained: %d", len(registry.entries))
	}
}
