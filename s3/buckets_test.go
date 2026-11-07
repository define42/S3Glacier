package s3

import (
	"archive/tar"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"glacier/config"
	"glacier/shared"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestBucketHandler(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		path      string
		count     string
		user      S3User
		status    int
		code      string
		wantCount string
	}{
		{name: "create requires explicit count", method: "PUT", path: "/archive", user: S3User{Write: true}, status: 400, code: "InvalidArgument"},
		{name: "create rejects noninteger count", method: "PUT", path: "/archive", count: "four", user: S3User{Write: true}, status: 400, code: "InvalidArgument"},
		{name: "create rejects zero count", method: "PUT", path: "/archive", count: "0", user: S3User{Write: true}, status: 400, code: "InvalidArgument"},
		{name: "create rejects excessive count", method: "PUT", path: "/archive", count: "65537", user: S3User{Write: true}, status: 400, code: "InvalidArgument"},
		{name: "create rejects invalid name", method: "PUT", path: "/Invalid", count: "4", user: S3User{Write: true}, status: 400, code: "InvalidBucketName"},
		{name: "reader cannot create", method: "PUT", path: "/archive", count: "4", user: S3User{Read: true}, status: 403, code: "AccessDenied"},
		{name: "writer creates four archives per hour", method: "PUT", path: "/archive", count: "4", user: S3User{Write: true}, status: 200, wantCount: "4"},
		{name: "default count is immutable", method: "PUT", path: "/data", count: "4", user: S3User{Write: true}, status: 409, code: "BucketAlreadyOwnedByYou"},
		{name: "default bucket head", method: "HEAD", path: "/data", user: S3User{Read: true}, status: 200, wantCount: "256"},
		{name: "missing bucket head", method: "HEAD", path: "/missing", user: S3User{Read: true}, status: 404},
		{name: "head requires read permission", method: "HEAD", path: "/data", user: S3User{Write: true}, status: 403},
		{name: "location lookup", method: "GET", path: "/data?location", user: S3User{Read: true}, status: 200, wantCount: "256"},
		{name: "missing bucket location", method: "GET", path: "/missing?location", user: S3User{Read: true}, status: 404, code: "NoSuchBucket"},
		{name: "object listing explicitly unsupported", method: "GET", path: "/data", user: S3User{Read: true}, status: 501, code: "NotImplemented"},
		{name: "bucket delete explicitly unsupported", method: "DELETE", path: "/data", user: S3User{Write: true}, status: 405, code: "MethodNotAllowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			request := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.count != "" {
				request.Header.Set(TarFilesPerHourHeader, tc.count)
			}
			request = mux.SetURLVars(request, map[string]string{"bucket": strings.TrimPrefix(request.URL.Path, "/")})
			response := httptest.NewRecorder()
			BucketHandler(store)(response, request, tc.user)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, tc.status, response.Body.String())
			}
			if tc.method == http.MethodHead && response.Body.Len() != 0 {
				t.Errorf("HEAD returned a body: %s", response.Body.String())
			}
			if tc.code != "" {
				assertErrorCode(t, response, tc.code)
			}
			if tc.wantCount != "" && response.Header().Get(TarFilesPerHourHeader) != tc.wantCount {
				t.Errorf("TAR files per hour = %q, want %q", response.Header().Get(TarFilesPerHourHeader), tc.wantCount)
			}
			if tc.method == "DELETE" && response.Header().Get("Allow") != "GET, HEAD, PUT" {
				t.Errorf("missing allowed methods: %q", response.Header().Get("Allow"))
			}
			if tc.name == "location lookup" {
				var location GetBucketLocation
				if err := xml.Unmarshal(response.Body.Bytes(), &location); err != nil {
					t.Fatalf("decode location: %v", err)
				}
				if location.XMLName.Local != "LocationConstraint" || location.XMLName.Space != s3Namespace {
					t.Errorf("unexpected location XML: %s", response.Body.String())
				}
			}
			defaultBucket, err := store.Get("data")
			if err != nil || defaultBucket.TarFilesPerHour != 256 {
				t.Errorf("default bucket changed: %+v, %v", defaultBucket, err)
			}
		})
	}
}

func TestBucketHandlerRecreationDoesNotChangeCount(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.Create("archive", 4); err != nil {
		t.Fatal(err)
	}
	for _, count := range []string{"4", "8"} {
		t.Run("count "+count, func(t *testing.T) {
			request := httptest.NewRequest("PUT", "/archive", nil)
			request.Header.Set(TarFilesPerHourHeader, count)
			request = mux.SetURLVars(request, map[string]string{"bucket": "archive"})
			response := httptest.NewRecorder()
			BucketHandler(store)(response, request, S3User{Write: true})
			if response.Code != http.StatusConflict {
				t.Fatalf("recreate returned %d, want 409", response.Code)
			}
			b, err := store.Get("archive")
			if err != nil || b.TarFilesPerHour != 4 {
				t.Fatalf("bucket count changed: %+v, %v", b, err)
			}
		})
	}
}

func TestBucketHandlerSignedCreation(t *testing.T) {
	store := openTestStore(t)
	router := authenticatedTestRouter(t, store)

	unsigned := httptest.NewRequest("PUT", "/unsigned", nil)
	unsigned.Header.Set(TarFilesPerHourHeader, "4")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, unsigned)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unsigned bucket creation returned %d", response.Code)
	}

	tampered := signedRequest("PUT", "/tampered", nil, "writer", "4")
	tampered.Header.Set(TarFilesPerHourHeader, "8")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, tampered)
	if response.Code != http.StatusForbidden {
		t.Fatalf("tampered count returned %d", response.Code)
	}
	assertErrorCode(t, response, "SignatureDoesNotMatch")
	if _, err := store.Get("tampered"); !errors.Is(err, bucket.ErrNotFound) {
		t.Fatalf("tampered request created bucket: %v", err)
	}

	request := signedRequest("PUT", "/archive", nil, "writer", "4")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("signed creation returned %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Location") != "/archive" {
		t.Errorf("creation location = %q", response.Header().Get("Location"))
	}

	request = signedRequest("PUT", "/readonly", nil, "reader", "4")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("reader created bucket: %d", response.Code)
	}
	if _, err := store.Get("readonly"); !errors.Is(err, bucket.ErrNotFound) {
		t.Fatalf("read-only request created bucket: %v", err)
	}
}

func TestObjectHandlerBucketIsolation(t *testing.T) {
	store := openTestStore(t)
	for _, name := range []string{"first", "second"} {
		if _, err := store.Create(name, 4); err != nil {
			t.Fatal(err)
		}
	}
	// Signed S3 permissions are sufficient even when the raw API uses tokens.
	oldReadToken := config.Settings.Get(config.READ_TOKEN)
	oldWriteToken := config.Settings.Get(config.WRITE_TOKEN)
	t.Cleanup(func() {
		config.Settings.Set(config.READ_TOKEN, "", oldReadToken)
		config.Settings.Set(config.WRITE_TOKEN, "", oldWriteToken)
	})
	t.Setenv(config.READ_TOKEN, "raw-read-token")
	t.Setenv(config.WRITE_TOKEN, "raw-write-token")
	config.Settings.Set(config.READ_TOKEN, "", "")
	config.Settings.Set(config.WRITE_TOKEN, "", "")
	router := authenticatedTestRouter(t, store)
	id := "20261107-1200-4000-8000-0000000000ff"
	for _, name := range []string{"first", "second"} {
		payload := []byte("object in " + name)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, signedRequest("PUT", "/"+name+"/"+id, payload, "writer", ""))
		if response.Code != http.StatusOK {
			t.Fatalf("upload to %s returned %d: %s", name, response.Code, response.Body.String())
		}
		hash := md5.Sum(payload)
		if want := `"` + hex.EncodeToString(hash[:]) + `"`; response.Header().Get("ETag") != want {
			t.Fatalf("PUT ETag = %q, want %q", response.Header().Get("ETag"), want)
		}
	}
	for _, name := range []string{"first", "second"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, signedRequest("GET", "/"+name+"/"+id, nil, "reader", ""))
		if response.Code != http.StatusOK || response.Body.String() != "object in "+name {
			t.Fatalf("download from %s: %d %q", name, response.Code, response.Body.String())
		}
		response = httptest.NewRecorder()
		router.ServeHTTP(response, signedRequest("HEAD", "/"+name+"/"+id, nil, "reader", ""))
		if response.Code != http.StatusOK || response.Body.Len() != 0 {
			t.Fatalf("HEAD in %s: %d %q", name, response.Code, response.Body.String())
		}
		if response.Header().Get("Content-Length") == "" {
			t.Error("HEAD did not return Content-Length")
		}
	}

	for _, method := range []string{"GET", "PUT", "HEAD"} {
		t.Run("missing bucket "+method, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest(method, "/missing/"+id, []byte("object"), "writer", ""))
			if response.Code != http.StatusNotFound {
				t.Fatalf("missing bucket returned %d: %s", response.Code, response.Body.String())
			}
		})
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("PUT", "/first/"+id, []byte("reader mutation"), "reader", ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("reader upload returned %d", response.Code)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("DELETE", "/first/"+id, nil, "writer", ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported deletion returned %d", response.Code)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("GET", "/first/"+id+"?uploadId=unsupported", nil, "reader", ""))
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported multipart query returned %d", response.Code)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("GET", "/first/20261107-1200-4000-8000-000000000001", nil, "reader", ""))
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing object returned %d: %s", response.Code, response.Body.String())
	}
	assertErrorCode(t, response, "NoSuchKey")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("HEAD", "/first/20261107-1200-4000-8000-000000000001", nil, "reader", ""))
	if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
		t.Fatalf("missing object HEAD returned %d: %s", response.Code, response.Body.String())
	}
}

func TestObjectHandlerRejectsBadDigest(t *testing.T) {
	store := openTestStore(t)
	router := authenticatedTestRouter(t, store)
	request := httptest.NewRequest("PUT", "/data/20261107-1200-4000-8000-0000000000ff", strings.NewReader("tampered"))
	hash := md5.Sum([]byte("original"))
	request.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(hash[:]))
	request = SignV2(*request, "writer", "secret", false)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatched checksum returned %d", response.Code)
	}
	assertErrorCode(t, response, "BadDigest")
}

func TestListBuckets(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.Create("archive", 4); err != nil {
		t.Fatal(err)
	}
	router := authenticatedTestRouter(t, store)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, signedRequest("GET", "/", nil, "reader", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("list buckets returned %d: %s", response.Code, response.Body.String())
	}
	var result listAllMyBucketsResult
	if err := xml.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode bucket list: %v", err)
	}
	if len(result.Buckets) != 2 || result.Buckets[0].Name != "archive" || result.Buckets[1].Name != "data" {
		t.Fatalf("bucket list = %+v", result.Buckets)
	}
	for _, b := range result.Buckets {
		if b.CreationDate == "" {
			t.Errorf("bucket %s lacks creation date", b.Name)
		}
	}
	if response.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("XML content type missing: %v", response.Header())
	}
}

func openTestStore(t *testing.T) *bucket.Store {
	t.Helper()
	store, err := bucket.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func authenticatedTestRouter(t *testing.T, store *bucket.Store) *mux.Router {
	t.Helper()
	ResetS3Users()
	AddS3User("writer", "secret", true, true)
	AddS3User("reader", "secret", false, true)
	t.Cleanup(ResetS3Users)
	router := mux.NewRouter()
	router.Handle("/", S3Security(ListBuckets(store)))
	router.Handle("/{bucket}", S3Security(BucketHandler(store)))
	router.Handle("/{bucket}/{id}", S3Security(ObjectHandler(store)))
	return router
}

func signedRequest(method, target string, body []byte, key, count string) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if count != "" {
		request.Header.Set(TarFilesPerHourHeader, count)
	}
	return SignV2(*request, key, "secret", false)
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("error content type = %q", response.Header().Get("Content-Type"))
	}
	var result s3Error
	if err := xml.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode error response: %v; body=%s", err, response.Body.String())
	}
	if result.Code != want {
		t.Errorf("error code = %q, want %q", result.Code, want)
	}
}

func TestObjectHandlerAppendsRepeatedPUTs(t *testing.T) {
	for _, version := range []string{"v2", "v4"} {
		t.Run(version, func(t *testing.T) {
			store := openTestStore(t)
			router := authenticatedTestRouter(t, store)
			b, err := store.Get("data")
			if err != nil {
				t.Fatal(err)
			}
			id := "20261107-1200-4000-8000-0000000000ff"
			payload := bytes.Repeat([]byte("original S3 content\n"), 30)
			put := func(body []byte) *httptest.ResponseRecorder {
				request := httptest.NewRequest("PUT", "/data/"+id, bytes.NewReader(body))
				if version == "v4" {
					hash := sha256.Sum256(body)
					request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(hash[:]))
					request = signer.SignV4(*request, "writer", "secret", "", "us-east-1")
				} else {
					request = SignV2(*request, "writer", "secret", false)
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				return response
			}
			first := put(payload)
			if first.Code != http.StatusOK {
				t.Fatalf("initial PUT: %d %s", first.Code, first.Body.String())
			}
			path, _, err := shared.GetBucketContainerFile(b, id)
			if err != nil {
				t.Fatal(err)
			}
			retry := put(payload)
			if retry.Code != http.StatusOK || retry.Header().Get("ETag") != first.Header().Get("ETag") {
				t.Fatalf("identical retry: %d etag=%q first=%q", retry.Code, retry.Header().Get("ETag"), first.Header().Get("ETag"))
			}
			if got := countS3ArchiveEntries(t, path, id); got != 2 {
				t.Fatalf("identical PUT stored %d entries, want 2", got)
			}
			different := []byte("different S3 content")
			duplicate := put(different)
			if duplicate.Code != http.StatusOK {
				t.Fatalf("PUT different content under the same UUID: %d %s", duplicate.Code, duplicate.Body.String())
			}
			hash := md5.Sum(different)
			if want := `"` + hex.EncodeToString(hash[:]) + `"`; duplicate.Header().Get("ETag") != want {
				t.Fatalf("duplicate PUT ETag=%q, want %q", duplicate.Header().Get("ETag"), want)
			}
			if got := countS3ArchiveEntries(t, path, id); got != 3 {
				t.Fatalf("different PUT stored %d entries, want 3", got)
			}
			previousStore := archive.Default
			archive.Default = archive.NewStore()
			t.Cleanup(func() { archive.Default = previousStore })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest("GET", "/data/"+id, nil, "reader", ""))
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
				t.Fatalf("GET after duplicate PUT: %d %q", response.Code, response.Body.Bytes())
			}
			response = httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest("HEAD", "/data/"+id, nil, "reader", ""))
			if response.Code != http.StatusOK || response.Header().Get("Content-Length") != strconv.Itoa(len(payload)) || response.Body.Len() != 0 {
				t.Fatalf("HEAD no longer describes the first entry: status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func countS3ArchiveEntries(t *testing.T, path, id string) int {
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

type s3ArchiveState struct {
	contents string
	modified int64
}

func snapshotS3Archive(t *testing.T, path string) map[string]s3ArchiveState {
	t.Helper()
	state := make(map[string]s3ArchiveState)
	for _, name := range []string{path, archive.CommitPath(path)} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		state[name] = s3ArchiveState{contents: string(data), modified: info.ModTime().UnixNano()}
	}
	return state
}

func TestObjectHandlerInvalidMetadataDoesNotQuarantine(t *testing.T) {
	for _, version := range []string{"v2", "v4"} {
		t.Run(version, func(t *testing.T) {
			store := openTestStore(t)
			b, err := store.Create("one-shard", 1)
			if err != nil {
				t.Fatal(err)
			}
			router := authenticatedTestRouter(t, store)
			id := "20261107-1200-4000-8000-000000000001"
			newID := "20261107-1200-4000-8000-000000000002"
			payload := []byte("original object")
			put := func(name string) *httptest.ResponseRecorder {
				request := httptest.NewRequest("PUT", "/one-shard/"+url.PathEscape(name), bytes.NewReader(payload))
				if version == "v4" {
					request = signer.SignV4(*request, "writer", "secret", "", "us-east-1")
				} else {
					request = SignV2(*request, "writer", "secret", false)
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				return response
			}
			first := put(id)
			if first.Code != http.StatusOK {
				t.Fatalf("initial PUT: %d %s", first.Code, first.Body.String())
			}
			path, _, err := shared.GetBucketContainerFile(b, id)
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotS3Archive(t, path)
			invalid := put("invalid\x00" + newID)
			if invalid.Code != http.StatusBadRequest {
				t.Fatalf("invalid metadata: %d %s", invalid.Code, invalid.Body.String())
			}
			assertErrorCode(t, invalid, "InvalidArgument")
			if !maps.Equal(snapshotS3Archive(t, path), before) {
				t.Fatal("invalid metadata modified archive or checkpoint")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest("GET", "/one-shard/"+id, nil, "reader", ""))
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), payload) {
				t.Fatalf("old object unavailable: %d %q", response.Code, response.Body.Bytes())
			}
			valid := put(newID)
			if valid.Code != http.StatusOK {
				t.Fatalf("valid PUT after invalid metadata: %d %s", valid.Code, valid.Body.String())
			}
		})
	}
}
