package main

import (
	"archive/tar"
	"bytes"
	"glacier/archive"
	"glacier/bucket"
	"glacier/shared"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestHTTPUploadsAppendRepeatedUUIDs(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv("DATA_FOLDER", root)
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("S3_READ_WRITE_USERS", "")
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	id := "20261107-1200-4000-8000-000000000001"
	payload := bytes.Repeat([]byte("original HTTP content\n"), 30)
	target := "/buckets/data/rawupload/" + id
	response := bucketRequest(t, router, "POST", target, "write-secret", payload)
	if response.Code != http.StatusOK {
		t.Fatalf("initial upload: %d %s", response.Code, response.Body.String())
	}
	b := bucket.Bucket{Name: "data", TarFilesPerHour: 256, Path: filepath.Join(root, "buckets", "data")}
	path, _, err := shared.GetBucketContainerFile(b, id)
	if err != nil {
		t.Fatal(err)
	}
	response = bucketRequest(t, router, "PUT", target, "write-secret", payload)
	if response.Code != http.StatusOK {
		t.Fatalf("identical raw retry: %d %s", response.Code, response.Body.String())
	}
	if got := countHTTPArchiveEntries(t, path, id); got != 2 {
		t.Fatalf("identical raw upload stored %d entries, want 2", got)
	}

	request := retryMultipartRequest(t, id, payload)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("identical multipart retry: %d %s", response.Code, response.Body.String())
	}
	if got := countHTTPArchiveEntries(t, path, id); got != 3 {
		t.Fatalf("identical multipart upload stored %d entries, want 3", got)
	}

	for i, tc := range []struct {
		name    string
		request *http.Request
	}{
		{name: "raw", request: httptest.NewRequest("PUT", target, bytes.NewReader([]byte("different HTTP content")))},
		{name: "multipart", request: retryMultipartRequest(t, id, []byte("different HTTP content"))},
	} {
		t.Run(tc.name+" different content", func(t *testing.T) {
			tc.request.Header.Set("Authorization", "Bearer write-secret")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, tc.request)
			if response.Code != http.StatusOK {
				t.Fatalf("same UUID with different content: %d %s", response.Code, response.Body.String())
			}
			if got, want := countHTTPArchiveEntries(t, path, id), 4+i; got != want {
				t.Fatalf("different content stored %d entries, want %d", got, want)
			}
		})
	}
	previousStore := archive.Default
	archive.Default = archive.NewStore()
	t.Cleanup(func() { archive.Default = previousStore })
	response = bucketRequest(t, router, "GET", "/buckets/data/get/"+id, "read-secret", nil)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
		t.Fatalf("GET after duplicate uploads: %d %q", response.Code, response.Body.Bytes())
	}
	response = bucketRequest(t, router, "HEAD", "/buckets/data/get/"+id, "read-secret", nil)
	if response.Code != http.StatusOK || response.Header().Get("Content-Length") != strconv.Itoa(len(payload)) || response.Body.Len() != 0 {
		t.Fatalf("HEAD no longer describes the first entry: status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func countHTTPArchiveEntries(t *testing.T, path, id string) int {
	t.Helper()
	reader, err := archive.Default.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tr := tar.NewReader(reader)
	count := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return count
		}
		if err != nil {
			t.Fatal(err)
		}
		if archive.IsInternalEntry(header) {
			continue
		}
		if header.Name != id {
			t.Fatalf("stored UUID=%q, want %q", header.Name, id)
		}
		count++
	}
}

func retryMultipartRequest(t *testing.T, id string, payload []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "retry-"+id+".txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/buckets/data/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", "Bearer write-secret")
	return request
}

type httpArchiveState struct {
	contents string
	modified int64
}

func snapshotHTTPArchive(t *testing.T, path string) map[string]httpArchiveState {
	t.Helper()
	state := make(map[string]httpArchiveState)
	for _, name := range []string{path, archive.CommitPath(path)} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		state[name] = httpArchiveState{contents: string(data), modified: info.ModTime().UnixNano()}
	}
	return state
}

func TestHTTPInvalidObjectMetadataDoesNotQuarantine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv("DATA_FOLDER", root)
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("S3_READ_WRITE_USERS", "")
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	response := bucketRequest(t, router, "POST", "/buckets", "write-secret", []byte(`{"name":"one-shard","tar_files_per_hour":1}`))
	if response.Code != http.StatusCreated {
		t.Fatalf("create bucket: %d %s", response.Code, response.Body.String())
	}
	id := "20261107-1200-4000-8000-000000000001"
	newID := "20261107-1200-4000-8000-000000000002"
	payload := []byte("original object")
	response = bucketRequest(t, router, "PUT", "/buckets/one-shard/rawupload/"+id, "write-secret", payload)
	if response.Code != http.StatusOK {
		t.Fatalf("initial upload: %d %s", response.Code, response.Body.String())
	}
	b := bucket.Bucket{Name: "one-shard", TarFilesPerHour: 1, Path: filepath.Join(root, "buckets", "one-shard")}
	path, _, err := shared.GetBucketContainerFile(b, id)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotHTTPArchive(t, path)
	response = bucketRequest(t, router, "PUT", "/buckets/one-shard/rawupload/"+url.PathEscape("invalid\x00"+newID), "write-secret", payload)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid object metadata: %d %s", response.Code, response.Body.String())
	}
	if !maps.Equal(snapshotHTTPArchive(t, path), before) {
		t.Fatal("invalid raw metadata modified archive or checkpoint")
	}
	request := retryMultipartRequest(t, "invalid\x00"+newID, payload)
	request.URL.Path = "/buckets/one-shard/upload"
	request.RequestURI = request.URL.RequestURI()
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid multipart metadata: %d %s", response.Code, response.Body.String())
	}
	if !maps.Equal(snapshotHTTPArchive(t, path), before) {
		t.Fatal("invalid multipart metadata modified archive or checkpoint")
	}
	response = bucketRequest(t, router, "GET", "/buckets/one-shard/get/"+id, "read-secret", nil)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
		t.Fatalf("old object became unavailable: %d %q", response.Code, response.Body.Bytes())
	}
	response = bucketRequest(t, router, "PUT", "/buckets/one-shard/rawupload/"+newID, "write-secret", []byte("valid new object"))
	if response.Code != http.StatusOK {
		t.Fatalf("valid append after invalid metadata: %d %s", response.Code, response.Body.String())
	}
}
