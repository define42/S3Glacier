package shared_test

import (
	"bytes"
	"errors"
	"fmt"
	"glacier/bucket"
	"glacier/config"
	"glacier/shared"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
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
	if len(entries) == 0 || len(entries) > 4 {
		t.Fatalf("created %d TAR files in one hour, want 1-4", len(entries))
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".tar" {
			t.Fatalf("unexpected archive entry: %s", entry.Name())
		}
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
