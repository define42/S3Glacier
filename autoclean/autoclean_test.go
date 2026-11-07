package autoclean

import (
	"errors"
	"glacier/prometheus"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gofrs/flock"
	dto "github.com/prometheus/client_model/go"
)

func TestArchiveHour(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "default bucket archive", path: "buckets/data/2026/11/07/10/0000.tar", want: true},
		{name: "bucket archive", path: "buckets/logs/2026/11/07/10/03.tar", want: true},
		{name: "archive outside buckets", path: "2026/11/07/10/ff.tar"},
		{name: "metadata", path: ".buckets/logs.json"},
		{name: "dated metadata", path: ".buckets/2026/11/07/10/00.tar"},
		{name: "unrelated tree", path: "backup/2026/11/07/10/00.tar"},
		{name: "extra nesting", path: "buckets/logs/nested/2026/11/07/10/00.tar"},
		{name: "invalid date", path: "buckets/data/2026/02/30/10/0000.tar"},
		{name: "invalid hour", path: "buckets/data/2026/11/07/24/0000.tar"},
		{name: "unpadded month", path: "buckets/data/2026/1/07/10/0000.tar"},
		{name: "different extension", path: "buckets/data/2026/11/07/10/0000.tar.tmp"},
		{name: "empty filename", path: "buckets/data/2026/11/07/10/.tar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hour, ok := archiveHour(filepath.FromSlash(tt.path))
			if ok != tt.want {
				t.Fatalf("archiveHour(%q) accepted = %v, want %v", tt.path, ok, tt.want)
			}
			if ok && !hour.Equal(time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)) {
				t.Fatalf("archiveHour(%q) = %v", tt.path, hour)
			}
		})
	}
}

func TestCollectArchives(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	want := []string{
		"buckets/z-last/2026/11/05/10/03.tar",
		"buckets/a-first/2026/11/06/10/01.tar",
		"buckets/data/2026/11/06/10/0000.tar",
		"buckets/a-first/2026/11/07/10/00.tar",
	}
	for _, path := range want {
		writeTestFile(t, root, path)
	}
	ignored := []string{
		".buckets/a-first.json",
		".buckets/2026/11/01/10/00.tar",
		"2026/11/01/10/ff.tar",
		"backup/2026/11/01/10/00.tar",
		"buckets/a-first/2026/02/30/10/00.tar",
		"buckets/a-first/2026/11/07/10/00.tmp",
	}
	for _, path := range ignored {
		writeTestFile(t, root, path)
	}
	link := filepath.Join(root, "buckets", "data", "2026", "11", "06", "10", "link.tar")
	if err := os.Symlink(filepath.Join(root, ".buckets", "a-first.json"), link); err != nil {
		t.Fatal(err)
	}
	candidates, err := collectArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		path, err := filepath.Rel(root, candidate.path)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, filepath.ToSlash(path))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("archive order = %v, want %v", got, want)
	}
}

func TestCollectArchivesMissingRoot(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "missing")
	candidates, err := collectArchives(root)
	if !os.IsNotExist(err) || len(candidates) != 0 {
		t.Fatalf("collectArchives(missing) = %v, %v; want no candidates and not-exist error", candidates, err)
	}
}

func TestRemoveArchiveDoesNotRecreateMissingFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "missing.tar")
	removed, err := removeArchive(path)
	if removed || !os.IsNotExist(err) {
		t.Fatalf("removeArchive(missing) = %v, %v", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing archive was recreated: %v", err)
	}
}

func TestCleanupArchivesRechecksDiskUsage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	oldest := writeTestFile(t, root, "buckets/z-last/2026/11/05/10/03.tar")
	newer := writeTestFile(t, root, "buckets/a-first/2026/11/06/10/00.tar")
	candidates, err := collectArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	retained, err := cleanupArchives(candidates, 75, func() (float64, error) {
		calls++
		if calls == 1 {
			return 90, nil
		}
		return 75, nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("cleanup error = %v, disk checks = %d; want nil, 2", err, calls)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Fatalf("oldest archive not removed: %v", err)
	}
	if len(retained) != 1 || retained[0].path != newer {
		t.Fatalf("retained archives = %v, want only %s", retained, newer)
	}
	if _, err := os.Stat(newer); err != nil {
		t.Fatalf("newer archive removed despite recovered disk usage: %v", err)
	}
}

func TestCleanupArchivesSkipsBusyLock(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	busy := writeTestFile(t, root, "buckets/data/2026/11/05/10/0000.tar")
	available := writeTestFile(t, root, "buckets/logs/2026/11/06/10/00.tar")
	lock := flock.New(busy, flock.SetFlag(os.O_RDWR))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		t.Fatalf("cannot acquire test lock: locked = %v, error = %v", locked, err)
	}
	t.Cleanup(func() { lock.Close() })
	candidates, err := collectArchives(root)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := cleanupArchives(candidates, 75, func() (float64, error) { return 90, nil })
	if err != nil || len(retained) != 1 || retained[0].path != busy {
		t.Fatalf("retained archives = %v, error = %v; want busy archive only", retained, err)
	}
	if _, err := os.Stat(busy); err != nil {
		t.Fatalf("busy archive was removed: %v", err)
	}
	if _, err := os.Stat(available); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not continue past busy archive: %v", err)
	}
}

func TestCleanupArchivesDiskStatFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		used float64
		err  error
	}{
		{name: "stat error", err: errors.New("disk unavailable")},
		{name: "not a number", used: math.NaN()},
		{name: "infinite usage", used: math.Inf(1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeTestFile(t, root, "buckets/logs/2026/11/05/10/00.tar")
			candidates, err := collectArchives(root)
			if err != nil {
				t.Fatal(err)
			}
			retained, err := cleanupArchives(candidates, 75, func() (float64, error) { return tt.used, tt.err })
			if err == nil || len(retained) != 1 {
				t.Fatalf("retained archives = %v, error = %v; want one retained archive and error", retained, err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("archive removed after invalid disk measurement: %v", err)
			}
		})
	}
}

func TestRunCleanupUpdatesGlobalWindowAndPreservesMetadata(t *testing.T) {
	root := t.TempDir()
	metadata := writeTestFile(t, root, ".buckets/logs.json")
	unmanaged := writeTestFile(t, root, "2026/11/01/10/ff.tar")
	writeTestFile(t, root, "buckets/z-last/2026/11/05/10/03.tar")
	writeTestFile(t, root, "buckets/data/2026/11/06/10/0000.tar")
	writeTestFile(t, root, "buckets/a-first/2026/11/07/10/00.tar")
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	if err := runCleanup(root, 75, func() (float64, error) { return 70, nil }, now); err != nil {
		t.Fatal(err)
	}
	assertDataWindow(t, 50)
	if err := runCleanup(root, 75, func() (float64, error) { return 90, nil }, now); err != nil {
		t.Fatal(err)
	}
	assertDataWindow(t, 0)
	if content, err := os.ReadFile(metadata); err != nil || string(content) != "archive" {
		t.Fatalf("bucket metadata changed: %q, %v", content, err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Fatalf("archive outside the bucket layout was removed: %v", err)
	}
}

func writeTestFile(t *testing.T, root, relative string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertDataWindow(t *testing.T, want float64) {
	t.Helper()
	var metric dto.Metric
	if err := prometheus.Current_data_window_in_hours.Write(&metric); err != nil {
		t.Fatal(err)
	}
	if got := metric.GetGauge().GetValue(); got != want {
		t.Fatalf("data window = %v hours, want %v", got, want)
	}
}
