package bucket_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"glacier/bucket"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenDefaultBucket(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeRoot, err := filepath.Rel(workingDirectory, root)
	if err != nil {
		t.Fatal(err)
	}
	store := openStore(t, relativeRoot)
	got, err := store.Get(bucket.DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "data" || got.TarFilesPerHour != 256 || got.Path != filepath.Join(root, "buckets", "data") || got.CreatedAt.IsZero() {
		t.Fatalf("default bucket = %+v", got)
	}
	if info, err := os.Stat(got.Path); err != nil || !info.IsDir() {
		t.Fatalf("default data directory was not created: info=%v err=%v", info, err)
	}
	created, err := store.Create("logs", 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []bucket.Bucket{got, created} {
		contents, err := os.ReadFile(filepath.Join(root, ".buckets", current.Name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var persisted struct {
			Layout string `json:"layout"`
		}
		if err := json.Unmarshal(contents, &persisted); err != nil || persisted.Layout != "bucket" {
			t.Fatalf("bucket %q layout=%q err=%v, want bucket", current.Name, persisted.Layout, err)
		}
		reopened, err := openStore(t, root).Get(current.Name)
		if err != nil || reopened != current {
			t.Fatalf("bucket changed after restart: got=%+v want=%+v err=%v", reopened, current, err)
		}
	}
	if _, err := store.Create("data", 4); !errors.Is(err, bucket.ErrExists) {
		t.Fatalf("changing default bucket: got %v, want ErrExists", err)
	}
}

func TestOpenRejectsInvalidConfigurations(t *testing.T) {
	t.Parallel()
	valid := `{"version":1,"layout":"bucket","name":"logs","tar_files_per_hour":4,"created_at":"2026-11-07T00:00:00Z"}`
	tests := []struct {
		name string
		file string
		body string
	}{
		{name: "truncated", file: "logs.json", body: `{"version":1`},
		{name: "version", file: "logs.json", body: strings.Replace(valid, `"version":1`, `"version":2`, 1)},
		{name: "layout", file: "logs.json", body: strings.Replace(valid, `"bucket"`, `"unknown"`, 1)},
		{name: "count", file: "logs.json", body: strings.Replace(valid, `"tar_files_per_hour":4`, `"tar_files_per_hour":0`, 1)},
		{name: "name", file: "logs.json", body: strings.Replace(valid, `"logs"`, `"UPPERCASE"`, 1)},
		{name: "filename mismatch", file: "other.json", body: valid},
		{name: "missing creation time", file: "logs.json", body: strings.Replace(valid, `,"created_at":"2026-11-07T00:00:00Z"`, ``, 1)},
		{name: "unknown field", file: "logs.json", body: strings.TrimSuffix(valid, "}") + `,"path":"elsewhere"}`},
		{name: "trailing json", file: "logs.json", body: valid + `{}`},
		{name: "oversized", file: "logs.json", body: valid + strings.Repeat(" ", 64<<10)},
		{name: "unsupported legacy layout", file: "logs.json", body: strings.Replace(valid, `"bucket"`, `"legacy"`, 1)},
		{name: "changed default count", file: "data.json", body: strings.Replace(valid, `"logs"`, `"data"`, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			openStore(t, root)
			if err := os.WriteFile(filepath.Join(root, ".buckets", tt.file), []byte(tt.body), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := bucket.Open(root); err == nil {
				t.Fatal("Open accepted invalid persisted configuration")
			}
		})
	}
}

func TestOpenRejectsOldLayoutWithoutChangingFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	metadata := filepath.Join(root, ".buckets", "data.json")
	archive := filepath.Join(root, "2025", "01", "02", "03", "ab.tar")
	for _, directory := range []string{filepath.Dir(metadata), filepath.Dir(archive)} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configuration := `{"version":1,"layout":"legacy","name":"data","tar_files_per_hour":256,"created_at":"2026-11-07T00:00:00Z"}`
	for name, contents := range map[string]string{metadata: configuration, archive: "existing archive"} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bucket.Open(root); err == nil || !strings.Contains(err.Error(), "unsupported layout") {
		t.Fatalf("Open old layout error=%v, want unsupported layout", err)
	}
	for name, want := range map[string]string{metadata: configuration, archive: "existing archive"} {
		contents, err := os.ReadFile(name)
		if err != nil || string(contents) != want {
			t.Fatalf("Open changed %q: contents=%q err=%v", name, contents, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "buckets", "data")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Open created a new layout after rejecting the configuration: %v", err)
	}
}

func TestOpenIgnoresIncompleteTemporaryConfiguration(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	openStore(t, root)
	if err := os.WriteFile(filepath.Join(root, ".buckets", ".tmp-interrupted"), []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := len(openStore(t, root).List()); got != 1 {
		t.Fatalf("List returned %d buckets, want 1", got)
	}
}

func TestOpenConcurrentBootstrap(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "new-root")
	const workers = 12
	errorsCh := make(chan error, workers)
	var done sync.WaitGroup
	for range workers {
		done.Go(func() {
			store, err := bucket.Open(root)
			if err == nil {
				_, err = store.Get(bucket.DefaultName)
			}
			errorsCh <- err
		})
	}
	done.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Errorf("concurrent Open: %v", err)
		}
	}
	if got := len(openStore(t, root).List()); got != 1 {
		t.Fatalf("List returned %d buckets, want 1", got)
	}
}

func TestCreateCountsPersist(t *testing.T) {
	t.Parallel()
	for _, count := range []int{1, 3, 4, bucket.DefaultTarFilesPerHour, 257, bucket.MaxTarFilesPerHour} {
		t.Run(fmt.Sprintf("count %d", count), func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			created, err := openStore(t, root).Create("archive-logs", count)
			if err != nil {
				t.Fatal(err)
			}
			if created.TarFilesPerHour != count || created.Path != filepath.Join(root, "buckets", "archive-logs") || created.CreatedAt.IsZero() {
				t.Fatalf("Create = %+v", created)
			}
			if info, err := os.Stat(created.Path); err != nil || !info.IsDir() {
				t.Fatalf("missing data directory: info=%v err=%v", info, err)
			}
			reopened, err := openStore(t, root).Get("archive-logs")
			if err != nil || reopened != created {
				t.Fatalf("restart = %+v, want %+v, err=%v", reopened, created, err)
			}
		})
	}
}

func TestCreateRejectsInvalidNamesAndCounts(t *testing.T) {
	t.Parallel()
	store := openStore(t, t.TempDir())
	invalidNames := []string{"", "ab", "UPPERCASE", "a.b", "a_b", "-abc", "abc-", "../logs", "a/b", strings.Repeat("a", 64)}
	invalidNames = append(invalidNames, "buckets", "files", "static", "get", "rawupload", "upload", "uuid", "uuidv1", "redirect", "metrics", "api")
	for i, name := range invalidNames {
		t.Run(fmt.Sprintf("name %d", i), func(t *testing.T) {
			if _, err := store.Create(name, 4); !errors.Is(err, bucket.ErrInvalidName) {
				t.Fatalf("Create(%q, 4) error = %v, want ErrInvalidName", name, err)
			}
		})
	}
	for _, count := range []int{-1, 0, bucket.MaxTarFilesPerHour + 1} {
		t.Run(fmt.Sprintf("count %d", count), func(t *testing.T) {
			if _, err := store.Create("valid-name", count); !errors.Is(err, bucket.ErrInvalidTarFiles) {
				t.Fatalf("Create count %d error = %v, want ErrInvalidTarFiles", count, err)
			}
		})
	}
	for _, name := range []string{"abc", "123", "abc-123", strings.Repeat("a", 63)} {
		if _, err := store.Create(name, 4); err != nil {
			t.Errorf("Create valid name %q: %v", name, err)
		}
	}
}

func TestCreateCannotChangeExistingBucket(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store := openStore(t, root)
	original, err := store.Create("logs", 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []*bucket.Store{store, openStore(t, root)} {
		for _, count := range []int{4, 256, 0} {
			if _, err := current.Create("logs", count); !errors.Is(err, bucket.ErrExists) {
				t.Errorf("repeated Create(%d) = %v, want ErrExists", count, err)
			}
		}
	}
	got, err := openStore(t, root).Get("logs")
	if err != nil || got != original {
		t.Fatalf("configuration changed: got=%+v want=%+v err=%v", got, original, err)
	}
}

func TestCreateConcurrentWinner(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stores := []*bucket.Store{openStore(t, root), openStore(t, root), openStore(t, root)}
	type result struct {
		bucket bucket.Bucket
		err    error
	}
	const workers = 24
	results := make(chan result, workers)
	start := make(chan struct{})
	var done sync.WaitGroup
	for i := range workers {
		done.Go(func() {
			<-start
			got, err := stores[i%len(stores)].Create("same-name", i+1)
			results <- result{bucket: got, err: err}
		})
	}
	close(start)
	done.Wait()
	close(results)
	winners := 0
	var winner bucket.Bucket
	for result := range results {
		if result.err == nil {
			winners++
			winner = result.bucket
		} else if !errors.Is(result.err, bucket.ErrExists) {
			t.Errorf("Create: %v", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful creates = %d, want 1", winners)
	}
	got, err := openStore(t, root).Get("same-name")
	if err != nil || got != winner {
		t.Fatalf("persisted bucket = %+v, winner=%+v, err=%v", got, winner, err)
	}
}

func TestCreateRejectsChangesToLoadedConfigurations(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"modified", "removed"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			store := openStore(t, root)
			original, err := store.Create("logs", 4)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, ".buckets", "logs.json")
			if change == "removed" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				contents = []byte(strings.Replace(string(contents), `"tar_files_per_hour":4`, `"tar_files_per_hour":8`, 1))
				if err := os.WriteFile(path, contents, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Create("another", 16); err == nil {
				t.Fatal("Create accepted changes to a loaded configuration")
			}
			unchanged, err := store.Get("logs")
			if err != nil || unchanged != original {
				t.Fatalf("loaded configuration changed: got=%+v want=%+v err=%v", unchanged, original, err)
			}
			if _, err := store.Get("another"); !errors.Is(err, bucket.ErrNotFound) {
				t.Fatalf("failed creation became visible: %v", err)
			}
		})
	}
}

func TestGetAndListReturnCopies(t *testing.T) {
	t.Parallel()
	store := openStore(t, t.TempDir())
	if _, err := store.Get("missing"); !errors.Is(err, bucket.ErrNotFound) {
		t.Fatalf("Get missing: %v", err)
	}
	if _, err := store.Create("logs", 4); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("logs")
	if err != nil {
		t.Fatal(err)
	}
	got.TarFilesPerHour = 8
	list := store.List()
	if len(list) != 2 || list[0].Name != "data" || list[1].Name != "logs" {
		t.Fatalf("List = %+v", list)
	}
	list[1].TarFilesPerHour = 16
	unchanged, err := store.Get("logs")
	if err != nil || unchanged.TarFilesPerHour != 4 {
		t.Fatalf("caller changed stored configuration: %+v err=%v", unchanged, err)
	}
	encoded, err := json.Marshal(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "path") {
		t.Fatalf("public JSON includes internal storage fields: %s", encoded)
	}
}

func openStore(t *testing.T, root string) *bucket.Store {
	t.Helper()
	store, err := bucket.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
