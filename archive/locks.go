package archive

import (
	"container/list"
	"context"
	"path/filepath"
	"sync"
)

// lockRegistry retains a path's lock identity while any holder or waiter refers
// to it. Its zero value is ready for use. It coordinates one process only.
type lockRegistry struct {
	mu      sync.Mutex
	entries map[string]*pathLock
}

type pathLock struct {
	readers int
	writer  bool
	refs    int // holders plus queued waiters
	waiters list.List
}

type lockWaiter struct {
	write   bool
	ready   chan struct{}
	element *list.Element
	granted bool
}

// acquire queues requests in arrival order, batching consecutive readers. A
// queued writer prevents later readers from bypassing it. try never queues.
// The returned release function is safe to call more than once.
func (r *lockRegistry) acquire(ctx context.Context, key string, write bool, try bool) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := filepath.Abs(key)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if r.entries == nil {
		r.entries = make(map[string]*pathLock)
	}
	entry := r.entries[key]
	if entry == nil {
		entry = &pathLock{}
		r.entries[key] = entry
	}
	if entry.waiters.Len() == 0 && !entry.writer && (!write || entry.readers == 0) {
		entry.refs++
		if write {
			entry.writer = true
		} else {
			entry.readers++
		}
		r.mu.Unlock()
		return r.releaseFunc(key, entry, write), nil
	}
	if try {
		r.mu.Unlock()
		return nil, ErrBusy
	}
	waiter := &lockWaiter{write: write, ready: make(chan struct{})}
	waiter.element = entry.waiters.PushBack(waiter)
	entry.refs++
	r.mu.Unlock()

	select {
	case <-waiter.ready:
		if err := ctx.Err(); err != nil {
			r.release(key, entry, write)
			return nil, err
		}
		return r.releaseFunc(key, entry, write), nil
	case <-ctx.Done():
		r.mu.Lock()
		if waiter.granted {
			r.releaseLocked(key, entry, write)
		} else {
			entry.waiters.Remove(waiter.element)
			entry.refs--
			r.grant(entry)
			r.removeIdle(key, entry)
		}
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (r *lockRegistry) releaseFunc(key string, entry *pathLock, write bool) func() {
	var once sync.Once
	return func() {
		once.Do(func() { r.release(key, entry, write) })
	}
}

func (r *lockRegistry) release(key string, entry *pathLock, write bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseLocked(key, entry, write)
}

func (r *lockRegistry) releaseLocked(key string, entry *pathLock, write bool) {
	if write {
		entry.writer = false
	} else {
		entry.readers--
	}
	entry.refs--
	r.grant(entry)
	r.removeIdle(key, entry)
}

// grant runs with r.mu held. Granting transfers a waiter's reference into a
// holder's reference before waking it, so cancellation cannot retire its entry.
func (r *lockRegistry) grant(entry *pathLock) {
	if entry.writer {
		return
	}
	for entry.waiters.Len() != 0 {
		waiter := entry.waiters.Front().Value.(*lockWaiter)
		if waiter.write && entry.readers != 0 {
			return
		}
		entry.waiters.Remove(waiter.element)
		waiter.element = nil
		waiter.granted = true
		if waiter.write {
			entry.writer = true
		} else {
			entry.readers++
		}
		close(waiter.ready)
		if waiter.write {
			return
		}
	}
}

func (r *lockRegistry) removeIdle(key string, entry *pathLock) {
	if entry.refs == 0 {
		delete(r.entries, key)
	}
}
