package s3

import (
	"context"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type listingSource struct {
	rows  map[string][]archive.ListEntry
	fail  map[string]error
	calls []string
}

func (s *listingSource) List(_ context.Context, path string, opts archive.ListOptions) ([]archive.ListEntry, error) {
	s.calls = append(s.calls, path)
	if err := s.fail[path]; err != nil {
		return nil, err
	}
	var rows []archive.ListEntry
	for _, row := range s.rows[path] {
		if strings.HasPrefix(row.Key, opts.Prefix) && row.Key > opts.After {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b archive.ListEntry) int { return strings.Compare(a.Key, b.Key) })
	return rows[:min(len(rows), opts.Limit)], nil
}

func addListingSource(t *testing.T, source *listingSource, root, relative string, rows ...archive.ListEntry) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	source.rows[path] = rows
	return path
}

func TestListBucketEntriesHourOrdering(t *testing.T) {
	t.Parallel()
	b := bucket.Bucket{Path: t.TempDir(), TarFilesPerHour: 4}
	source := &listingSource{rows: make(map[string][]archive.ListEntry), fail: make(map[string]error)}
	first := archive.ListEntry{Key: "20261107-1200-4000-8000-000000000001", Size: 10}
	second := archive.ListEntry{Key: "20261107-1230-4000-8000-000000000002", Size: 20}
	// The first shard contains the larger key: completing one shard is not enough.
	shard0 := addListingSource(t, source, b.Path, "2026/11/07/12/0000.tar", second)
	shard1 := addListingSource(t, source, b.Path, "2026/11/07/12/0001.tar", first)
	later := addListingSource(t, source, b.Path, "2026/11/07/13/0000.tar")
	source.fail[later] = archive.ErrCorrupt
	got, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1})
	if err != nil || !slices.Equal(got, []archive.ListEntry{first, second}) {
		t.Fatalf("first page=%v err=%v", got, err)
	}
	if !slices.Equal(source.calls, []string{shard0, shard1}) {
		t.Fatalf("visited %v; should finish the first hour without opening a later archive", source.calls)
	}

	source.calls = nil
	got, err = listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1000, prefix: "20261107-1230"})
	if err != nil || !slices.Equal(got, []archive.ListEntry{second}) || !slices.Equal(source.calls, []string{shard0, shard1}) {
		t.Fatalf("minute prefix=%v err=%v archives=%v; both shards in its hour must be checked", got, err, source.calls)
	}

	source.calls = nil
	got, err = listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1000, after: "20261107-13"})
	if !errors.Is(err, archive.ErrCorrupt) || got != nil || !slices.Equal(source.calls, []string{later}) {
		t.Fatalf("cursor did not skip the preceding hour: rows=%v err=%v archives=%v", got, err, source.calls)
	}
}

func TestListBucketEntriesExtendedOrdering(t *testing.T) {
	t.Parallel()
	b := bucket.Bucket{Path: t.TempDir(), TarFilesPerHour: 4}
	source := &listingSource{rows: make(map[string][]archive.ListEntry)}
	february := archive.ListEntry{Key: "20260201-1200-4000-8000-000000000001", Size: 1}
	februaryNext := archive.ListEntry{Key: "20260201-1201-4000-8000-000000000002", Size: 2}
	january := archive.ListEntry{Key: "20260131-1281-4000-8000-000000000003", Size: 3}
	addListingSource(t, source, b.Path, "2026/02/01/12/0000.tar", february, februaryNext)
	addListingSource(t, source, b.Path, "2026/03/03/12/0000.tar", january)
	got, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1, extended: true})
	if err != nil || !slices.Equal(got, []archive.ListEntry{january, february}) || len(source.calls) != 2 {
		t.Fatalf("extended first page=%v err=%v archives=%v", got, err, source.calls)
	}
	source.calls = nil
	got, err = listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1, prefix: "20260131", extended: true})
	if err != nil || !slices.Equal(got, []archive.ListEntry{january}) || len(source.calls) != 2 {
		t.Fatalf("extended prefix missed the normalized March folder: rows=%v err=%v archives=%v", got, err, source.calls)
	}
}

func TestListBucketEntriesCommonPrefixes(t *testing.T) {
	t.Parallel()
	b := bucket.Bucket{Path: t.TempDir(), TarFilesPerHour: 4}
	source := &listingSource{rows: make(map[string][]archive.ListEntry)}
	first := archive.ListEntry{Key: "20261107-", CommonPrefix: true}
	second := archive.ListEntry{Key: "20261108-", CommonPrefix: true}
	addListingSource(t, source, b.Path, "2026/11/07/12/0000.tar", first)
	addListingSource(t, source, b.Path, "2026/11/07/12/0001.tar", first)
	addListingSource(t, source, b.Path, "2026/11/07/13/0000.tar", first)
	addListingSource(t, source, b.Path, "2026/11/08/00/0000.tar", second)
	got, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1, delimiter: "-"})
	if err != nil || !slices.Equal(got, []archive.ListEntry{first, second}) {
		t.Fatalf("common-prefix page=%v err=%v", got, err)
	}
	got, err = listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1, delimiter: "-", after: first.Key})
	if err != nil || !slices.Equal(got, []archive.ListEntry{second}) {
		t.Fatalf("continued common-prefix page=%v err=%v", got, err)
	}
}

func TestListBucketEntriesErrorsAndLayout(t *testing.T) {
	t.Parallel()
	b := bucket.Bucket{Path: filepath.Join(t.TempDir(), "missing"), TarFilesPerHour: 4}
	source := &listingSource{rows: make(map[string][]archive.ListEntry), fail: make(map[string]error)}
	if rows, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 1}); err != nil || len(rows) != 0 {
		t.Fatalf("missing archive directory: rows=%v err=%v", rows, err)
	}
	for _, relative := range []string{
		"2026/02/30/12/0000.tar", "2026/11/07/24/0000.tar", "2026/1/07/12/0000.tar",
		"2026/11/07/12/0004.tar", "2026/11/07/12/000A.tar", "2026/11/07/12/not-a-shard.tar", "2026/11/07/12/0000.commit",
	} {
		path := addListingSource(t, source, b.Path, relative)
		source.fail[path] = errors.New("unrelated file must not be listed")
	}
	valid := addListingSource(t, source, b.Path, "2026/11/07/12/0000.tar", archive.ListEntry{Key: "20261107-1200-4000-8000-000000000001", Size: 1})
	missing := addListingSource(t, source, b.Path, "2026/11/07/12/0001.tar")
	source.fail[missing] = os.ErrNotExist
	rows, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 10})
	if err != nil || len(rows) != 1 || !slices.Equal(source.calls, []string{valid, missing}) {
		t.Fatalf("layout/deletion filtering: rows=%v err=%v archives=%v", rows, err, source.calls)
	}
	source.fail[missing] = archive.ErrUnavailable
	if rows, err := listBucketEntries(t.Context(), source, b, listQuery{maxKeys: 10}); !errors.Is(err, archive.ErrUnavailable) || rows != nil {
		t.Fatalf("returned partial success after archive failure: rows=%v err=%v", rows, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := listBucketEntries(ctx, source, b, listQuery{maxKeys: 10}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled listing error=%v", err)
	}
}
