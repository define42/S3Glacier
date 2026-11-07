package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"glacier/bucket"
	"glacier/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
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
