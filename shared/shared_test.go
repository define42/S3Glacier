package shared_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"glacier/archive"
	"glacier/bucket"
	"glacier/config"
	"glacier/prometheus"
	"glacier/shared"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	dto "github.com/prometheus/client_model/go"
)

const (
	v1ID = "13814000-1dd2-11b2-8000-000000000001"
	v4ID = "20261107-1036-40f1-b34f-02d7517a01d3"
)

func TestGetBucketContainerFileShardMapping(t *testing.T) {
	configureStorage(t)
	tests := []struct {
		count   int
		v1Shard string
		v4Shard string
	}{
		{count: 1, v1Shard: "0000.tar", v4Shard: "0000.tar"},
		{count: 4, v1Shard: "0000.tar", v4Shard: "0003.tar"},
		{count: 7, v1Shard: "0000.tar", v4Shard: "0005.tar"},
		{count: 256, v1Shard: "00e4.tar", v4Shard: "005f.tar"},
		{count: 257, v1Shard: "00fb.tar", v4Shard: "002c.tar"},
		{count: 65536, v1Shard: "c3e4.tar", v4Shard: "fc5f.tar"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("count %d", tt.count), func(t *testing.T) {
			root := t.TempDir()
			store := openBuckets(t, root)
			b, err := store.Create("mapping", tt.count)
			if err != nil {
				t.Fatal(err)
			}
			objects := []struct {
				name string
				id   string
				date string
				file string
			}{
				{name: "uuidv1", id: v1ID, date: "1970/01/01/00", file: tt.v1Shard},
				{name: "uuidv4", id: v4ID, date: "2026/11/07/10", file: tt.v4Shard},
			}
			for _, object := range objects {
				t.Run(object.name, func(t *testing.T) {
					got, id, err := shared.GetBucketContainerFile(b, object.id)
					want := filepath.Join(b.Path, filepath.FromSlash(object.date), object.file)
					if err != nil || got != want || id != object.id {
						t.Fatalf("path=%q id=%q err=%v, want path=%q id=%q", got, id, err, want, object.id)
					}
					index, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(got), ".tar"), 16, 64)
					if err != nil || index >= uint64(tt.count) {
						t.Fatalf("shard index %d outside count %d: %v", index, tt.count, err)
					}
					reloaded, err := openBuckets(t, root).Get(b.Name)
					if err != nil {
						t.Fatal(err)
					}
					afterRestart, _, err := shared.GetBucketContainerFile(reloaded, object.id)
					if err != nil || afterRestart != got {
						t.Fatalf("mapping changed after restart: before=%q after=%q err=%v", got, afterRestart, err)
					}
				})
			}
		})
	}
}

func TestGetBucketContainerFileUsesSameLayoutForDefaultBucket(t *testing.T) {
	root := configureStorage(t)
	store := openBuckets(t, root)
	data, err := store.Get(bucket.DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.Create("other-data", 256)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		id   string
		path string
	}{
		{name: "uuidv1", id: v1ID, path: "1970/01/01/00/00e4.tar"},
		{name: "uuidv4", id: v4ID, path: "2026/11/07/10/005f.tar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := filepath.Join(root, "buckets", "data", filepath.FromSlash(tt.path))
			got, id, err := shared.GetBucketContainerFile(data, tt.id)
			if err != nil || got != want || id != tt.id {
				t.Fatalf("default mapping = %q, %q, %v; want %q", got, id, err, want)
			}
			otherPath, _, err := shared.GetBucketContainerFile(other, tt.id)
			otherWant := filepath.Join(root, "buckets", "other-data", filepath.FromSlash(tt.path))
			if err != nil || otherPath != otherWant {
				t.Fatalf("named bucket mapping = %q, %v; want %q", otherPath, err, otherWant)
			}
			contents := []byte("default bucket object")
			if uploaded := uploadObject(t, data, tt.id, contents); uploaded != want {
				t.Fatalf("upload path = %q, want %q", uploaded, want)
			}
			reloaded, err := openBuckets(t, root).Get(bucket.DefaultName)
			if err != nil {
				t.Fatal(err)
			}
			out := getObject(reloaded, tt.id)
			if out.Code != http.StatusOK || !bytes.Equal(out.Body.Bytes(), contents) {
				t.Fatalf("default bucket after restart: status=%d body=%q", out.Code, out.Body.Bytes())
			}
		})
	}
}

func TestGetBucketContainerFileRejectsInvalidIDsAndCounts(t *testing.T) {
	root := configureStorage(t)
	b := bucket.Bucket{Name: "testing", Path: root, TarFilesPerHour: 4}
	invalidIDs := []string{
		"", "not-a-uuid", "20261107-1036-30f1-b34f-02d7517a01d3",
		"00261107-1036-40f1-b34f-02d7517a01d3", "20261307-1036-40f1-b34f-02d7517a01d3",
		"20260230-1036-40f1-b34f-02d7517a01d3", "20261107-2436-40f1-b34f-02d7517a01d3",
	}
	for i, id := range invalidIDs {
		t.Run(fmt.Sprintf("invalid id %d", i), func(t *testing.T) {
			if _, _, err := shared.GetBucketContainerFile(b, id); err == nil {
				t.Fatalf("invalid ID %q was accepted", id)
			}
		})
	}
	for _, count := range []int{-1, 0, bucket.MaxTarFilesPerHour + 1} {
		t.Run(fmt.Sprintf("invalid count %d", count), func(t *testing.T) {
			invalid := b
			invalid.TarFilesPerHour = count
			if _, _, err := shared.GetBucketContainerFile(invalid, v4ID); !errors.Is(err, bucket.ErrInvalidTarFiles) {
				t.Fatalf("invalid count error = %v, want ErrInvalidTarFiles", err)
			}
		})
	}
}

func TestUploadToBucketIsolatesSameID(t *testing.T) {
	root := configureStorage(t)
	store := openBuckets(t, root)
	first, err := store.Create("first", 4)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create("second", 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{v1ID, v4ID} {
		t.Run(id, func(t *testing.T) {
			firstData := bytes.Repeat([]byte("first bucket content\n"), 20)
			secondData := bytes.Repeat([]byte("second bucket content\n"), 20)
			firstPath := uploadObject(t, first, id, firstData)
			secondPath := uploadObject(t, second, id, secondData)
			if firstPath == secondPath {
				t.Fatalf("buckets share an archive: %s", firstPath)
			}
			for _, current := range []struct {
				bucket bucket.Bucket
				data   []byte
			}{{bucket: first, data: firstData}, {bucket: second, data: secondData}} {
				out := getObject(current.bucket, id)
				if out.Code != http.StatusOK || !bytes.Equal(out.Body.Bytes(), current.data) {
					t.Fatalf("bucket %s GET status=%d body=%q", current.bucket.Name, out.Code, out.Body.Bytes())
				}
			}
		})
	}
}

func TestUploadToBucketUsesAtMostConfiguredTarFiles(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("four-shards", 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 128 {
		id := fmt.Sprintf("20261107-1036-4000-8000-%012x", i)
		uploadObject(t, b, id, []byte(fmt.Sprintf("object %d", i)))
	}
	entries, err := os.ReadDir(filepath.Join(b.Path, "2026", "11", "07", "10"))
	if err != nil {
		t.Fatal(err)
	}
	archives := 0
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected archive directory: %s", entry.Name())
		}
		switch filepath.Ext(entry.Name()) {
		case ".tar":
			archives++
			if _, err := os.Stat(archive.CommitPath(filepath.Join(b.Path, "2026", "11", "07", "10", entry.Name()))); err != nil {
				t.Fatalf("archive lacks checkpoint: %s: %v", entry.Name(), err)
			}
		case ".commit":
		default:
			t.Fatalf("unexpected archive entry: %s", entry.Name())
		}
	}
	if archives == 0 || archives > 4 {
		t.Fatalf("created %d TAR files in one hour, want 1-4", archives)
	}
	for _, i := range []int{0, 63, 127} {
		id := fmt.Sprintf("20261107-1036-4000-8000-%012x", i)
		out := getObject(b, id)
		if out.Code != http.StatusOK || out.Body.String() != fmt.Sprintf("object %d", i) {
			t.Fatalf("GET %s status=%d body=%q", id, out.Code, out.Body.String())
		}
	}
}

func TestGetBucketFileMissingDoesNotCreateArchive(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("empty-bucket", 4)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := shared.GetBucketContainerFile(b, v4ID)
	if err != nil {
		t.Fatal(err)
	}
	out := getObject(b, v4ID)
	if out.Code != http.StatusNotFound {
		t.Fatalf("GET missing object status=%d body=%q, want 404", out.Code, out.Body.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GET created archive %q: %v", path, err)
	}
	entries, err := os.ReadDir(b.Path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("GET changed empty bucket: entries=%v err=%v", entries, err)
	}
}

func configureStorage(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for key, value := range map[string]string{
		config.DATA_FOLDER: root, config.EXTEND_LIFE_SUPPORT: "false",
		config.READ_TOKEN: "", config.WRITE_TOKEN: "",
	} {
		t.Setenv(key, value)
		config.Settings.Set(key, "", value)
	}
	return root
}

func openBuckets(t *testing.T, root string) *bucket.Store {
	t.Helper()
	store, err := bucket.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func uploadObject(t *testing.T, b bucket.Bucket, id string, data []byte) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/"+b.Name+"/"+id, bytes.NewReader(data))
	gotID, path, err := shared.UploadToBucket(request, b, id, data)
	if err != nil || gotID != id {
		t.Fatalf("upload bucket=%s id=%q gotID=%q err=%v", b.Name, id, gotID, err)
	}
	return path
}

func getObject(b bucket.Bucket, id string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/"+b.Name+"/"+id, nil)
	request = mux.SetURLVars(request, map[string]string{"id": id})
	out := httptest.NewRecorder()
	shared.GetBucketFile(out, request, b)
	return out
}

func TestUploadToBucketIdempotentRetries(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "uncompressed", payload: []byte("original content")},
		{name: "compressed", payload: bytes.Repeat([]byte("compressible original content\n"), 40)},
		{name: "empty", payload: []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := configureStorage(t)
			b, err := openBuckets(t, root).Get("data")
			if err != nil {
				t.Fatal(err)
			}
			beforeCounter := completedUploadCount(t)
			path := uploadObject(t, b, v4ID, tc.payload)
			beforeFiles := archiveState(t, path)
			previousStore := archive.Default
			archive.Default = archive.NewStore()
			t.Cleanup(func() { archive.Default = previousStore })
			request := httptest.NewRequest(http.MethodPut, "/data/retry", bytes.NewReader(tc.payload))
			id, gotPath, err := shared.UploadToBucket(request, b, "retry-"+v4ID+".txt", tc.payload)
			if err != nil || id != v4ID || gotPath != path {
				t.Fatalf("retry: id=%q path=%q err=%v", id, gotPath, err)
			}
			if got := archiveState(t, path); !maps.Equal(got, beforeFiles) {
				t.Fatal("identical retry changed archive or checkpoint")
			}
			conflict := append(bytes.Clone(tc.payload), []byte("different")...)
			request = httptest.NewRequest(http.MethodPut, "/data/conflict", bytes.NewReader(conflict))
			if _, _, err := shared.UploadToBucket(request, b, v4ID, conflict); !errors.Is(err, archive.ErrConflict) {
				t.Fatalf("different content error=%v, want ErrConflict", err)
			}
			if got := archiveState(t, path); !maps.Equal(got, beforeFiles) {
				t.Fatal("conflicting retry changed archive or checkpoint")
			}
			out := getObject(b, v4ID)
			if out.Code != http.StatusOK || !bytes.Equal(out.Body.Bytes(), tc.payload) {
				t.Fatalf("original object changed: %d %q", out.Code, out.Body.Bytes())
			}
			if got := completedUploadCount(t) - beforeCounter; got != 1 {
				t.Fatalf("completed uploads increased by %v, want 1", got)
			}
		})
	}
}

func TestUploadToBucketConcurrentIdenticalRetries(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Get("data")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("same concurrent content\n"), 40)
	beforeCounter := completedUploadCount(t)
	start := make(chan struct{})
	results := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			request := httptest.NewRequest(http.MethodPut, "/data/concurrent", bytes.NewReader(payload))
			_, _, err := shared.UploadToBucket(request, b, v4ID, payload)
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent retry failed: %v", err)
		}
	}
	if got := completedUploadCount(t) - beforeCounter; got != 1 {
		t.Fatalf("completed uploads increased by %v, want 1", got)
	}
	path, _, err := shared.GetBucketContainerFile(b, v4ID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := archive.Default.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tr := tar.NewReader(reader)
	objects := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !archive.IsInternalEntry(header) {
			objects++
		}
	}
	if objects != 1 {
		t.Fatalf("concurrent retries stored %d object entries, want 1", objects)
	}
}

type archiveFileState struct {
	contents string
	modified int64
}

func archiveState(t *testing.T, path string) map[string]archiveFileState {
	t.Helper()
	state := make(map[string]archiveFileState)
	for _, name := range []string{path, archive.CommitPath(path)} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		state[name] = archiveFileState{contents: string(data), modified: info.ModTime().UnixNano()}
	}
	return state
}

func completedUploadCount(t *testing.T) float64 {
	t.Helper()
	var metric dto.Metric
	if err := prometheus.RawUploadDoneProcessed.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}

func TestGetBucketFileRejectsArchiveWithoutCheckpoint(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Get("data")
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := shared.GetBucketContainerFile(b, v4ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	// A standalone empty TAR is deliberately missing the required identity and checkpoint.
	unmanaged := make([]byte, 1024)
	if err := os.WriteFile(path, unmanaged, 0600); err != nil {
		t.Fatal(err)
	}
	out := getObject(b, v4ID)
	if out.Code != http.StatusInternalServerError {
		t.Fatalf("unmanaged archive returned %d: %s", out.Code, out.Body.String())
	}
	if _, err := os.Stat(archive.CommitPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created checkpoint for unmanaged archive: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, unmanaged) {
		t.Fatalf("read modified unmanaged archive: %v", err)
	}
}

func TestUploadToBucketInvalidFilenameDoesNotQuarantine(t *testing.T) {
	root := configureStorage(t)
	b, err := openBuckets(t, root).Create("one-shard", 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("original object")
	path := uploadObject(t, b, v4ID, payload)
	before := archiveState(t, path)
	newID := "20261107-1036-40f1-b34f-02d7517a01d4"
	request := httptest.NewRequest(http.MethodPut, "/one-shard/invalid", bytes.NewReader(payload))
	if _, _, err := shared.UploadToBucket(request, b, "invalid\x00"+newID, payload); !errors.Is(err, archive.ErrInvalidEntry) {
		t.Fatalf("invalid metadata error=%v, want ErrInvalidEntry", err)
	}
	if !maps.Equal(archiveState(t, path), before) {
		t.Fatal("invalid metadata changed the committed archive or checkpoint")
	}
	out := getObject(b, v4ID)
	if out.Code != http.StatusOK || !bytes.Equal(out.Body.Bytes(), payload) {
		t.Fatalf("invalid metadata quarantined old data: %d %q", out.Code, out.Body.Bytes())
	}
	uploadObject(t, b, newID, []byte("valid new object"))
	out = getObject(b, newID)
	if out.Code != http.StatusOK || out.Body.String() != "valid new object" {
		t.Fatalf("valid append after invalid metadata failed: %d %q", out.Code, out.Body.Bytes())
	}
}
