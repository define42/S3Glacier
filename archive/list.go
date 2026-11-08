package archive

import (
	"archive/tar"
	"container/heap"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
)

const (
	defaultMetadataCacheBytes = 32 << 20
	maxListEntries            = 1001 // One S3 page plus its lookahead entry.
)

// ListOptions selects a page of logical object names within one archive.
// After is exclusive and applies to the resulting key, including common prefixes.
// Limit is capped at 1001; nonpositive limits return no entries.
type ListOptions struct {
	Prefix, After, Delimiter string
	Limit                    int
}

// ListEntry describes the first committed occurrence of an object name. Size is
// its original, uncompressed size. CommonPrefix entries have no object size.
type ListEntry struct {
	Key          string
	Size         int64
	CommonPrefix bool
}

type objectMetadata struct {
	key  string
	size int64
}

type metadataIndex struct {
	path, generation string
	dataEnd          int64
	objects          []objectMetadata // Immutable, sorted, first occurrence per name.
	bytes            int64
	oversized        bool
}

// Accounting deliberately exceeds the retained slice/string cost and includes
// map/list overhead. Building is serialized and capped separately at this same
// budget; a large archive never creates an unbounded temporary index.
type metadataCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     list.List
	bytes   int64
	limit   int64
	build   chan struct{}
}

func (c *metadataCache) initialize() {
	if c.entries == nil {
		c.entries = make(map[string]*list.Element)
		c.build = make(chan struct{}, 1)
		if c.limit == 0 {
			c.limit = defaultMetadataCacheBytes
		}
	}
}

func (c *metadataCache) get(path string) *metadataIndex {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initialize()
	if e := c.entries[path]; e != nil {
		c.lru.MoveToFront(e)
		return e.Value.(*metadataIndex)
	}
	return nil
}

func (c *metadataCache) remove(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[path]; e != nil {
		c.bytes -= e.Value.(*metadataIndex).bytes
		c.lru.Remove(e)
		delete(c.entries, path)
	}
}

func (c *metadataCache) put(index *metadataIndex) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initialize()
	if e := c.entries[index.path]; e != nil {
		c.bytes -= e.Value.(*metadataIndex).bytes
		c.lru.Remove(e)
		delete(c.entries, index.path)
	}
	if index.bytes > c.limit {
		return
	}
	for c.bytes+index.bytes > c.limit {
		e := c.lru.Back()
		old := e.Value.(*metadataIndex)
		c.bytes -= old.bytes
		delete(c.entries, old.path)
		c.lru.Remove(e)
	}
	c.entries[index.path] = c.lru.PushFront(index)
	c.bytes += index.bytes
}

func (c *metadataCache) acquireBuild(ctx context.Context) (func(), int64, error) {
	c.mu.Lock()
	c.initialize()
	gate, limit := c.build, c.limit
	c.mu.Unlock()
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return nil, 0, err
		}
		return func() { <-gate }, limit, nil
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

// List returns sorted, distinct names from a committed archive snapshot. A lazy,
// byte-bounded metadata cache accelerates repeated listings; appends never build
// or consult it. Growing archives scan only the newly committed suffix. Archives
// larger than the cache budget use a bounded page collector instead.
//
// Scans hold an open file but no archive lock. The committed prefix is immutable,
// and generation revalidation rejects cleanup/recreation during a scan with
// os.ErrNotExist. Concurrent appends may appear on a subsequent request. Every
// request validates and confirms the checkpoint, including metadata cache hits.
func (s *Store) List(ctx context.Context, path string, opts ListOptions) ([]ListEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.Limit <= 0 {
		return nil, nil
	}
	opts.Limit = min(opts.Limit, maxListEntries)
	path, err := canonical(path)
	if err != nil {
		return nil, err
	}
	r, index, err := s.listSnapshot(ctx, path)
	if err != nil {
		return nil, err
	}
	if index != nil && !index.oversized && index.dataEnd == r.commit.DataEnd {
		return s.listCached(ctx, path, r, index, opts)
	}
	// Never retain a file or archive lock while queued behind another build.
	if err := r.Close(); err != nil {
		return nil, err
	}
	release, budget, err := s.lists.acquireBuild(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, index, err = s.listSnapshot(ctx, path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if index != nil && !index.oversized && index.dataEnd == r.commit.DataEnd {
		return s.listCached(ctx, path, r, index, opts)
	}
	next, entries, err := s.buildMetadata(ctx, r, index, budget, opts)
	if err = errors.Join(err, r.Close()); err != nil {
		s.lists.remove(path)
		return nil, err
	}
	if err := s.finishList(ctx, path, r.commit, next); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Store) listSnapshot(ctx context.Context, path string) (*Reader, *metadataIndex, error) {
	r, err := s.Open(ctx, path)
	if err != nil {
		s.lists.remove(path)
		return nil, nil, err
	}
	// lockRegistry's release is idempotent; Reader.Close still owns the FD.
	r.release()
	index := s.lists.get(path)
	if index != nil && (index.generation != r.commit.Generation || index.dataEnd > r.commit.DataEnd) {
		s.lists.remove(path)
		index = nil
	}
	return r, index, nil
}

func (s *Store) listCached(ctx context.Context, path string, r *Reader, index *metadataIndex, opts ListOptions) ([]ListEntry, error) {
	if err := r.Close(); err != nil {
		return nil, err
	}
	entries, err := selectMetadata(ctx, index.objects, opts)
	if err != nil {
		return nil, err
	}
	if err := s.finishList(ctx, path, r.commit, nil); err != nil {
		return nil, err
	}
	return entries, nil
}

// The cache mutex is never held while waiting for an archive lock. Publication
// under the short shared lock cannot race durable deletion of that generation.
func (s *Store) finishList(ctx context.Context, path string, captured checkpoint, index *metadataIndex) error {
	if err := s.step("list.scanned"); err != nil {
		return err
	}
	release, err := s.locks.acquire(ctx, path, false, false)
	if err != nil {
		return err
	}
	defer release()
	if err = checkParents(path); err == nil {
		err = s.healthy(path)
	}
	if err == nil {
		_, err = regularFile(path)
	}
	var current checkpoint
	if err == nil {
		current, err = readCheckpoint(path)
		if errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("%w: existing archive has no checkpoint", ErrCorrupt)
		}
	}
	if err == nil && current.Generation != captured.Generation {
		err = os.ErrNotExist
	}
	if err == nil && (current.State != "ready" || current.DataEnd < captured.DataEnd) {
		err = fmt.Errorf("%w: committed prefix shrank during listing", ErrCorrupt)
	}
	if err != nil {
		s.lists.remove(path)
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if index != nil {
		s.lists.put(index)
	}
	return nil
}

func (s *Store) buildMetadata(ctx context.Context, r *Reader, old *metadataIndex, budget int64, opts ListOptions) (*metadataIndex, []ListEntry, error) {
	next := &metadataIndex{
		path: r.Name(), generation: r.commit.Generation, dataEnd: r.commit.DataEnd,
		bytes: int64(256 + len(r.Name()) + len(r.commit.Generation)),
	}
	page := newListCollector(opts)
	start := int64(0)
	var base []objectMetadata
	if old != nil && !old.oversized {
		base = old.objects
		start = old.dataEnd
		next.bytes = old.bytes
		for _, object := range base {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			page.add(object)
		}
	}
	next.oversized = next.bytes > budget || (old != nil && old.oversized)
	added := make(map[string]objectMetadata)
	if err := s.step("list.scan"); err != nil {
		return nil, nil, err
	}
	err := scanMetadata(ctx, r.file, start, r.commit.DataEnd, func(object objectMetadata) error {
		if err := s.step("list.header"); err != nil {
			return err
		}
		page.add(object)
		if next.oversized {
			return nil
		}
		if _, exists := added[object.key]; exists {
			return nil
		}
		if _, exists := slices.BinarySearchFunc(base, object.key, compareMetadataKey); exists {
			return nil
		}
		cost := int64(128 + len(object.key))
		if next.bytes+cost > budget {
			next.oversized = true
			added = nil
			return nil
		}
		object.key = strings.Clone(object.key)
		added[object.key] = object
		next.bytes += cost
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if next.oversized {
		next.bytes = int64(256 + len(next.path) + len(next.generation))
	} else {
		next.objects = mergeMetadata(base, added)
	}
	return next, page.sorted(), nil
}

func scanMetadata(ctx context.Context, f *os.File, start, end int64, visit func(objectMetadata) error) error {
	section := io.NewSectionReader(f, start, end-start)
	reader := tar.NewReader(section)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			offset, _ := section.Seek(0, io.SeekCurrent)
			if offset != end-start {
				return fmt.Errorf("%w: premature TAR end within committed prefix", ErrCorrupt)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: listing TAR headers: %v", ErrCorrupt, err)
		}
		if IsInternalEntry(h) {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Name == "" || strings.HasSuffix(h.Name, "/") {
			return fmt.Errorf("%w: invalid object header", ErrCorrupt)
		}
		size := h.Size
		if h.Mode == 1 {
			size = int64(h.Uid)
		}
		if size < 0 {
			return fmt.Errorf("%w: negative original object size", ErrCorrupt)
		}
		if err := visit(objectMetadata{key: h.Name, size: size}); err != nil {
			return err
		}
	}
}

func compareMetadataKey(object objectMetadata, key string) int {
	return strings.Compare(object.key, key)
}

func mergeMetadata(base []objectMetadata, added map[string]objectMetadata) []objectMetadata {
	if len(added) == 0 {
		return base
	}
	delta := make([]objectMetadata, 0, len(added))
	for _, object := range added {
		delta = append(delta, object)
	}
	slices.SortFunc(delta, func(a, b objectMetadata) int { return strings.Compare(a.key, b.key) })
	if len(base) == 0 {
		return delta
	}
	merged := make([]objectMetadata, 0, len(base)+len(delta))
	for len(base) > 0 && len(delta) > 0 {
		if base[0].key < delta[0].key {
			merged = append(merged, base[0])
			base = base[1:]
		} else {
			merged = append(merged, delta[0])
			delta = delta[1:]
		}
	}
	merged = append(merged, base...)
	return append(merged, delta...)
}

func logicalEntry(object objectMetadata, opts ListOptions) (ListEntry, bool) {
	if !strings.HasPrefix(object.key, opts.Prefix) {
		return ListEntry{}, false
	}
	entry := ListEntry{Key: object.key, Size: object.size}
	if opts.Delimiter != "" {
		if at := strings.Index(object.key[len(opts.Prefix):], opts.Delimiter); at >= 0 {
			entry.Key = object.key[:len(opts.Prefix)+at+len(opts.Delimiter)]
			entry.Size = 0
			entry.CommonPrefix = true
		}
	}
	return entry, entry.Key > opts.After
}

func selectMetadata(ctx context.Context, objects []objectMetadata, opts ListOptions) ([]ListEntry, error) {
	start := sort.Search(len(objects), func(i int) bool {
		return objects[i].key >= opts.Prefix && objects[i].key > opts.After
	})
	entries := make([]ListEntry, 0, opts.Limit)
	for _, object := range objects[start:] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(object.key, opts.Prefix) {
			break
		}
		entry, keep := logicalEntry(object, opts)
		if !keep || (len(entries) > 0 && entries[len(entries)-1].Key == entry.Key) {
			continue
		}
		entry.Key = strings.Clone(entry.Key)
		entries = append(entries, entry)
		if len(entries) == opts.Limit {
			break
		}
	}
	return entries, nil
}

type listCollector struct {
	opts    ListOptions
	entries listHeap
	seen    map[string]struct{}
}

func newListCollector(opts ListOptions) *listCollector {
	return &listCollector{opts: opts, seen: make(map[string]struct{}, opts.Limit)}
}

func (c *listCollector) add(object objectMetadata) {
	entry, keep := logicalEntry(object, c.opts)
	if !keep {
		return
	}
	if _, exists := c.seen[entry.Key]; exists {
		return
	}
	if len(c.entries) == c.opts.Limit && entry.Key >= c.entries[0].Key {
		return
	}
	entry.Key = strings.Clone(entry.Key)
	if len(c.entries) == c.opts.Limit {
		delete(c.seen, c.entries[0].Key)
		c.entries[0] = entry
		heap.Fix(&c.entries, 0)
	} else {
		heap.Push(&c.entries, entry)
	}
	// Once evicted, a key cannot enter again: the maximum retained key only
	// decreases. Keeping just these keys preserves first-match metadata.
	c.seen[entry.Key] = struct{}{}
}

func (c *listCollector) sorted() []ListEntry {
	slices.SortFunc(c.entries, func(a, b ListEntry) int { return strings.Compare(a.Key, b.Key) })
	return c.entries
}

type listHeap []ListEntry

func (h listHeap) Len() int           { return len(h) }
func (h listHeap) Less(i, j int) bool { return h[i].Key > h[j].Key }
func (h listHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *listHeap) Push(value any)    { *h = append(*h, value.(ListEntry)) }
func (h *listHeap) Pop() any {
	last := len(*h) - 1
	value := (*h)[last]
	*h = (*h)[:last]
	return value
}
