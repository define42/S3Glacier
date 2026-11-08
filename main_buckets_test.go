package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"glacier/bucket"
	"glacier/s3"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestBucketRoundTripAndRestart(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), "archive-data")
	// The process working directory is deliberately unrelated to its data root.
	t.Chdir(t.TempDir())
	t.Setenv("DATA_FOLDER", dataRoot)
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("S3_READ_WRITE_USERS", "")
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	defaultID := "20261107-1200-4000-8000-0000000000ff"

	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	response := bucketRequest(t, router, "POST", "/rawupload/"+defaultID, "write-secret", []byte("default bucket object"))
	if response.Code != http.StatusOK {
		t.Fatalf("default upload failed: %d %q", response.Code, response.Body.String())
	}
	response = bucketRequest(t, router, "GET", "/get/"+defaultID, "read-secret", nil)
	if response.Code != http.StatusOK || response.Body.String() != "default bucket object" {
		t.Fatalf("default read failed: %d %q", response.Code, response.Body.String())
	}
	defaultArchives, err := filepath.Glob(filepath.Join(dataRoot, "buckets", "data", "2026", "11", "07", "12", "*.tar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultArchives) != 1 {
		t.Fatalf("default upload created %d archives under buckets/data, want 1", len(defaultArchives))
	}
	if matched, err := regexp.MatchString(`^[0-9a-f]{4}\.tar$`, filepath.Base(defaultArchives[0])); err != nil || !matched {
		t.Fatalf("default archive does not use a four-digit hexadecimal shard: %s, %v", defaultArchives[0], err)
	}
	if relative, err := filepath.Rel(filepath.Join(dataRoot, "buckets", "data"), defaultArchives[0]); err != nil || !filepath.IsLocal(relative) {
		t.Fatalf("default archive escaped its bucket: %s, %v", defaultArchives[0], err)
	}

	for _, tc := range []struct {
		name  string
		count int
	}{
		{name: "four-files", count: 4},
		{name: "seven-files", count: 7},
	} {
		body := fmt.Sprintf(`{"name":%q,"tar_files_per_hour":%d}`, tc.name, tc.count)
		response := bucketRequest(t, router, "POST", "/buckets", "write-secret", []byte(body))
		if response.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", tc.name, response.Code, response.Body.String())
		}
		for i := range 32 {
			id := fmt.Sprintf("20261107-1200-4000-8000-%012x", i)
			path := "/buckets/" + tc.name + "/rawupload/" + id
			if tc.name == "seven-files" {
				path = "/rawupload/" + id + "?bucket=" + tc.name
			}
			payload := []byte(fmt.Sprintf("%s object %d", tc.name, i))
			response := bucketRequest(t, router, "POST", path, "write-secret", payload)
			if response.Code != http.StatusOK {
				t.Fatalf("upload %s/%s: %d %s", tc.name, id, response.Code, response.Body.String())
			}
		}
		archives, err := filepath.Glob(filepath.Join(dataRoot, "buckets", tc.name, "2026", "11", "07", "12", "*.tar"))
		if err != nil {
			t.Fatal(err)
		}
		if len(archives) == 0 || len(archives) > tc.count {
			t.Fatalf("%s created %d hourly TAR files; maximum is %d", tc.name, len(archives), tc.count)
		}
	}

	for _, name := range []string{"data", "four-files"} {
		body := fmt.Sprintf(`{"name":%q,"tar_files_per_hour":8}`, name)
		response := bucketRequest(t, router, "POST", "/buckets", "write-secret", []byte(body))
		if response.Code != http.StatusConflict {
			t.Fatalf("%s bucket count change returned %d: %s", name, response.Code, response.Body.String())
		}
		for _, method := range []string{"PUT", "PATCH"} {
			response = bucketRequest(t, router, method, "/buckets/"+name, "write-secret", []byte(`{"tar_files_per_hour":8}`))
			if response.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s bucket count change via %s returned %d", name, method, response.Code)
			}
		}
	}

	restarted, err := NewServer()
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	for _, tc := range []struct {
		name  string
		count int
	}{
		{name: "data", count: 256},
		{name: "four-files", count: 4},
		{name: "seven-files", count: 7},
	} {
		response := bucketRequest(t, restarted, "GET", "/buckets/"+tc.name, "read-secret", nil)
		if response.Code != http.StatusOK {
			t.Fatalf("inspect %s after restart: %d %s", tc.name, response.Code, response.Body.String())
		}
		var b bucket.Bucket
		if err := json.Unmarshal(response.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		if b.Name != tc.name || b.TarFilesPerHour != tc.count {
			t.Fatalf("persisted bucket = %+v, want name=%s count=%d", b, tc.name, tc.count)
		}
		if tc.name == "data" {
			continue
		}
		for i := range 32 {
			id := fmt.Sprintf("20261107-1200-4000-8000-%012x", i)
			path := "/buckets/" + tc.name + "/get/" + id
			if tc.name == "seven-files" {
				path = "/get/" + id + "?bucket=" + tc.name
			}
			response := bucketRequest(t, restarted, "GET", path, "read-secret", nil)
			want := fmt.Sprintf("%s object %d", tc.name, i)
			if response.Code != http.StatusOK || response.Body.String() != want {
				t.Fatalf("read %s/%s after restart: %d %q, want %q", tc.name, id, response.Code, response.Body.String(), want)
			}
		}
	}
	response = bucketRequest(t, restarted, "GET", "/get/"+defaultID, "read-secret", nil)
	if response.Code != http.StatusOK || response.Body.String() != "default bucket object" {
		t.Fatalf("default read after restart: %d %q", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataRoot, "2026")); !os.IsNotExist(err) {
		t.Fatalf("unexpected year directory directly under data root: %v", err)
	}
	if _, err := os.Stat("files"); !os.IsNotExist(err) {
		t.Fatalf("unexpected files relative to working directory: %v", err)
	}
}

func TestBucketManagementAuthorization(t *testing.T) {
	t.Setenv("DATA_FOLDER", filepath.Join(t.TempDir(), "data"))
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("S3_READ_WRITE_USERS", "")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	response := bucketRequest(t, router, "POST", "/buckets", "read-secret", []byte(`{"name":"forbidden","tar_files_per_hour":4}`))
	if response.Code != http.StatusForbidden {
		t.Fatalf("read token created bucket: %d", response.Code)
	}
	response = bucketRequest(t, router, "GET", "/buckets", "write-secret", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("write token listed buckets: %d", response.Code)
	}
	response = bucketRequest(t, router, "GET", "/buckets", "read-secret", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"data"`) {
		t.Fatalf("read token list: %d %s", response.Code, response.Body.String())
	}
	for _, method := range []string{"GET", "POST"} {
		response = bucketRequest(t, router, method, "/buckets", "", []byte(`{"name":"unsigned","tar_files_per_hour":4}`))
		if response.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated %s /buckets returned %d", method, response.Code)
		}
	}
}

func TestS3BucketRoutes(t *testing.T) {
	t.Setenv("DATA_FOLDER", filepath.Join(t.TempDir(), "data"))
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "s3reader=secret")
	t.Setenv("S3_READ_WRITE_USERS", "s3writer=secret")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("PUT", "/s3-archive", nil)
	request.Header.Set(s3.TarFilesPerHourHeader, "4")
	request = s3.SignV2(*request, "s3writer", "secret", false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("signed bucket creation: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest("PUT", "/s3-archive", nil)
	request.Header.Set(s3.TarFilesPerHourHeader, "8")
	request = s3.SignV2(*request, "s3writer", "secret", false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("signed recreation: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest("PUT", "/readonly", nil)
	request.Header.Set(s3.TarFilesPerHourHeader, "4")
	request = s3.SignV2(*request, "s3reader", "secret", false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("S3 reader created bucket: %d", response.Code)
	}

	id := "20261107-1200-4000-8000-000000000001"
	payload := "object through signed bucket route"
	request = httptest.NewRequest("PUT", "/s3-archive/"+id, strings.NewReader(payload))
	request = s3.SignV2(*request, "s3writer", "secret", false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("signed object upload: %d %s", response.Code, response.Body.String())
	}
	for _, method := range []string{"GET", "HEAD"} {
		request = httptest.NewRequest(method, "/s3-archive/"+id, nil)
		request = s3.SignV2(*request, "s3reader", "secret", false)
		response = httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("signed object %s: %d %s", method, response.Code, response.Body.String())
		}
		if method == "GET" && response.Body.String() != payload {
			t.Fatalf("signed GET body = %q, want %q", response.Body.String(), payload)
		}
		if method == "HEAD" && response.Body.Len() != 0 {
			t.Fatalf("signed HEAD returned body %q", response.Body.String())
		}
	}

	request = httptest.NewRequest("GET", "/", nil)
	request = s3.SignV2(*request, "s3reader", "secret", false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/xml" {
		t.Fatalf("signed root listing: %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "<Name>s3-archive</Name>") || !strings.Contains(response.Body.String(), "<Name>data</Name>") {
		t.Fatalf("signed root did not list both buckets: %s", response.Body.String())
	}
	response = bucketRequest(t, router, "GET", "/", "", nil)
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("unsigned root no longer serves GUI: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest("GET", "/data/?location", nil)
	request = s3.SignV2(*request, "s3reader", "secret", false)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "LocationConstraint") {
		t.Fatalf("default S3 location: %d %s", response.Code, response.Body.String())
	}
}

func TestObjectRoutesRejectUUIDv1(t *testing.T) {
	dataRoot := t.TempDir()
	t.Setenv("DATA_FOLDER", dataRoot)
	t.Setenv("READ_TOKEN", "read-secret")
	t.Setenv("WRITE_TOKEN", "write-secret")
	t.Setenv("S3_READ_ONLY_USERS", "")
	t.Setenv("S3_READ_WRITE_USERS", "s3writer=secret")
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}

	const oldID = "13814000-1dd2-11b2-8000-000000000001"
	for _, protocol := range []string{"HTTP", "S3V2", "S3V4"} {
		t.Run(protocol, func(t *testing.T) {
			for _, key := range []struct {
				name string
				id   string
			}{
				{name: "UUIDv1", id: oldID},
				{name: "embedded_filename", id: "capture-" + oldID + ".pcap"},
				{name: "timestamp_prefix", id: "20261107-1200-1000-8000-000000000001"},
			} {
				t.Run(key.name, func(t *testing.T) {
					for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodHead} {
						t.Run(method, func(t *testing.T) {
							var body []byte
							if method == http.MethodPut {
								body = []byte("UUIDv1 must not be archived")
							}
							target := "/data/" + key.id
							if protocol == "HTTP" {
								target = "/buckets/data/get/" + key.id
								if method == http.MethodPut {
									target = "/buckets/data/rawupload/" + key.id
								}
							}
							request := httptest.NewRequest(method, "http://example.com"+target, bytes.NewReader(body))
							switch protocol {
							case "HTTP":
								token := "read-secret"
								if method == http.MethodPut {
									token = "write-secret"
								}
								request.Header.Set("Authorization", "Bearer "+token)
							case "S3V2":
								request = s3.SignV2(*request, "s3writer", "secret", false)
							case "S3V4":
								digest := sha256.Sum256(body)
								request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
								request = signer.SignV4(*request, "s3writer", "secret", "", "us-east-1")
							}
							response := httptest.NewRecorder()
							router.ServeHTTP(response, request)
							if response.Code != http.StatusBadRequest {
								t.Fatalf("UUIDv1 request returned %d: %s", response.Code, response.Body.String())
							}
							if protocol != "HTTP" && method != http.MethodHead && !strings.Contains(response.Body.String(), "<Code>InvalidArgument</Code>") {
								t.Fatalf("S3 rejection is not an invalid object key: %s", response.Body.String())
							}
						})
					}
				})
			}
		})
	}

	t.Run("multipart_filename", func(t *testing.T) {
		request := retryMultipartRequest(t, oldID, []byte("UUIDv1 must not be archived"))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("UUIDv1 multipart upload returned %d: %s", response.Code, response.Body.String())
		}
	})
	entries, err := os.ReadDir(filepath.Join(dataRoot, "buckets", "data"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected UUIDv1 requests created archive files or directories: %v", entries)
	}
}

func bucketRequest(t *testing.T, handler http.Handler, method, target, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if strings.HasPrefix(target, "/buckets") && method == "POST" && len(body) > 0 && body[0] == '{' {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
