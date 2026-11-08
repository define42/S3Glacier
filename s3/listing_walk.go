package s3

import (
	"cmp"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/bucket"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type archiveLister interface {
	List(context.Context, string, archive.ListOptions) ([]archive.ListEntry, error)
}

type listEntryHeap struct {
	entries []archive.ListEntry
	seen    map[string]struct{}
	limit   int
}

func (h listEntryHeap) Len() int           { return len(h.entries) }
func (h listEntryHeap) Less(i, j int) bool { return h.entries[i].Key > h.entries[j].Key }
func (h listEntryHeap) Swap(i, j int)      { h.entries[i], h.entries[j] = h.entries[j], h.entries[i] }
func (h *listEntryHeap) Push(value any)    { h.entries = append(h.entries, value.(archive.ListEntry)) }
func (h *listEntryHeap) Pop() any {
	last := len(h.entries) - 1
	entry := h.entries[last]
	h.entries[last] = archive.ListEntry{}
	h.entries = h.entries[:last]
	return entry
}

func (h *listEntryHeap) offer(entry archive.ListEntry) {
	if _, exists := h.seen[entry.Key]; exists {
		return
	}
	if h.Len() == h.limit {
		if entry.Key >= h.entries[0].Key {
			return
		}
		old := heap.Pop(h).(archive.ListEntry)
		delete(h.seen, old.Key)
	}
	if h.seen == nil {
		h.seen = make(map[string]struct{})
	}
	h.seen[entry.Key] = struct{}{}
	heap.Push(h, entry)
}

var errListPageComplete = errors.New("listing page is complete")

// listBucketEntries retains at most maxKeys+1 logical results. Without month
// offsets, fixed-width UUID date/hour prefixes have the directory order, so a
// full hour of shards can complete a page without discovering later hours.
func listBucketEntries(ctx context.Context, lister archiveLister, b bucket.Bucket, q listQuery) ([]archive.ListEntry, error) {
	collected := &listEntryHeap{limit: q.maxKeys + 1}
	options := archive.ListOptions{Prefix: q.prefix, After: q.after, Delimiter: q.delimiter, Limit: q.maxKeys + 1}
	err := filepath.WalkDir(b.Path, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil // Cleanup may remove a directory after its parent was read.
			}
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == b.Path {
			if !entry.IsDir() {
				return fmt.Errorf("%w: bucket path is not a real directory", archive.ErrCorrupt)
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(b.Path, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if !validListDirectory(parts) {
			return filepath.SkipDir
		}
		directoryPrefix := strings.Join(parts, "")
		if len(parts) == 4 {
			directoryPrefix = strings.Join(parts[:3], "") + "-" + parts[3]
		}
		if !q.extended {
			if !strings.HasPrefix(q.prefix, directoryPrefix) && !strings.HasPrefix(directoryPrefix, q.prefix) {
				return filepath.SkipDir
			}
			if len(q.after) >= len(directoryPrefix) && directoryPrefix < q.after[:len(directoryPrefix)] {
				return filepath.SkipDir
			}
		}
		if len(parts) != 4 {
			return nil
		}
		files, err := os.ReadDir(path)
		if errors.Is(err, os.ErrNotExist) {
			return filepath.SkipDir
		}
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !file.Type().IsRegular() || !validListShard(file.Name(), b.TarFilesPerHour) {
				continue
			}
			entries, err := lister.List(ctx, filepath.Join(path, file.Name()), options)
			if errors.Is(err, os.ErrNotExist) {
				continue // The archive was evicted or recreated during its snapshot.
			}
			if err != nil {
				return err
			}
			for _, candidate := range entries {
				collected.offer(candidate)
			}
		}
		if !q.extended && collected.Len() == collected.limit {
			return errListPageComplete
		}
		return filepath.SkipDir
	})
	if err != nil && !errors.Is(err, errListPageComplete) {
		return nil, err
	}
	slices.SortFunc(collected.entries, func(a, b archive.ListEntry) int { return cmp.Compare(a.Key, b.Key) })
	return collected.entries, nil
}

func validListDirectory(parts []string) bool {
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for i, part := range parts {
		length := 2
		if i == 0 {
			length = 4
		}
		if len(part) != length || strings.IndexFunc(part, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return false
		}
	}
	complete := []string{"2000", "01", "01", "00"}
	copy(complete, parts)
	date := strings.Join(complete, "/")
	parsed, err := time.Parse("2006/01/02/15", date)
	return err == nil && parsed.Year() >= 2000 && parsed.Year() <= 2110 && parsed.Format("2006/01/02/15") == date
}

func validListShard(name string, count int) bool {
	if len(name) != 8 || !strings.HasSuffix(name, ".tar") {
		return false
	}
	index, err := strconv.ParseUint(name[:4], 16, 16)
	return err == nil && int(index) < count && fmt.Sprintf("%04x.tar", index) == name
}
