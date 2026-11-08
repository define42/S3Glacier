package s3

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"glacier/bucket"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestObjectHandlerMetadataRoundTrip(t *testing.T) {
	for _, version := range []string{"v2", "v4"} {
		t.Run(version, func(t *testing.T) {
			store := openTestStore(t)
			router := authenticatedTestRouter(t, store)
			const target = "/data/20261107-1200-4000-8000-000000000001"
			payload := bytes.Repeat([]byte("compressed object with metadata\n"), 20)
			request := httptest.NewRequest(http.MethodPut, "http://example.com"+target, bytes.NewReader(payload))
			want := map[string]string{
				"Content-Type": "application/x-s3glacier-test", "Content-Disposition": `attachment; filename="report.bin"`,
				"Content-Encoding": "identity", "Content-Language": "da", "Cache-Control": "max-age=60",
				"Expires": "Wed, 11 Nov 2026 12:00:00 GMT", "X-Amz-Meta-Project": "archive",
			}
			for name, value := range want {
				request.Header.Set(name, value)
			}
			request.Header.Add("X-Amz-Meta-Labels", "first")
			request.Header.Add("X-Amz-Meta-Labels", "second")
			request.Header.Set("Cookie", "private=secret")
			request.Header.Set("Set-Cookie", "injected=true")
			request.Header.Set("X-Internal-Trace", "private-trace")
			request.Header.Set("ETag", `"forged"`)
			request.Header.Set("Last-Modified", "Wed, 11 Nov 2020 12:00:00 GMT")
			request = signMetadataRequest(request, version, payload)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("PUT: %d %s", response.Code, response.Body.String())
			}
			digest := md5.Sum(payload)
			want["ETag"] = `"` + hex.EncodeToString(digest[:]) + `"`
			want["X-Amz-Meta-Labels"] = "first,second"
			want["Content-Length"] = strconv.Itoa(len(payload))
			want["Last-Modified"] = "Sat, 07 Nov 2026 00:00:00 GMT"
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				request := httptest.NewRequest(method, "http://example.com"+target, nil)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, signMetadataRequest(request, version, nil))
				if response.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", method, response.Code, response.Body.String())
				}
				for name, value := range want {
					if got := response.Header().Get(name); got != value {
						t.Errorf("%s header %s=%q, want %q", method, name, got, value)
					}
				}
				for _, name := range []string{"Authorization", "Cookie", "Set-Cookie", "X-Internal-Trace", "Content-MD5", "X-Amz-Date", "X-Amz-Content-Sha256", "X-Amz-Decoded-Content-Length"} {
					if got := response.Header().Get(name); got != "" {
						t.Errorf("%s leaked request header %s=%q", method, name, got)
					}
				}
				if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), payload) {
					t.Error("GET changed object content")
				}
				if method == http.MethodHead && response.Body.Len() != 0 {
					t.Error("HEAD returned a body")
				}
			}
		})
	}
}

func TestObjectHandlerQueryMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, header, query, want, code string
		status                          int
		v2, tamper, repeat, oversized   bool
	}{
		{name: "query metadata", query: "query-value", want: "query-value", status: 200},
		{name: "matching header and query", header: "same", query: "same", want: "same", status: 200},
		{name: "repeated query values", query: "first", repeat: true, want: "first,second", status: 200},
		{name: "decode encoded word once", query: "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte("=?UTF-8?B?aGVsbG8=?=")) + "?=", want: "=?UTF-8?B?aGVsbG8=?=", status: 200},
		{name: "conflicting signed header and query", header: "header-value", query: "query-value", code: "InvalidRequest", status: 400},
		{name: "conflicting metadata after signature normalization", header: "header  value", query: "header value", code: "InvalidArgument", status: 400},
		{name: "combined budget", oversized: true, code: "MetadataTooLarge", status: 400},
		{name: "query header injection", query: "value\r\nX-Injected: yes", code: "InvalidArgument", status: 400},
		{name: "tampered signed query", query: "signed", tamper: true, code: "SignatureDoesNotMatch", status: 403},
		{name: "V2 does not authenticate query metadata", query: "unsigned", v2: true, code: "NotImplemented", status: 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			router := authenticatedTestRouter(t, store)
			const target = "/data/20261107-1200-4000-8000-000000000001"
			payload := []byte("metadata from a signed query")
			request := httptest.NewRequest(http.MethodPut, "http://example.com"+target, bytes.NewReader(payload))
			query := make(url.Values)
			query.Set("x-AmZ-MeTa-Project", tc.query)
			if tc.repeat {
				query.Add("x-AmZ-MeTa-Project", "second")
			}
			if tc.header != "" {
				request.Header.Set("X-Amz-Meta-Project", tc.header)
			}
			if tc.oversized {
				request.Header.Set("X-Amz-Meta-Header", strings.Repeat("h", 1200))
				query.Set("x-AmZ-MeTa-Project", strings.Repeat("q", 1200))
			}
			request.URL.RawQuery = query.Encode()
			if tc.v2 {
				request = SignV2(*request, "writer", "secret", false)
			} else {
				request = signer.PreSignV4(*request, "writer", "secret", "", "us-east-1", 300)
			}
			if tc.tamper {
				query := request.URL.Query()
				query.Set("x-AmZ-MeTa-Project", "changed")
				request.URL.RawQuery = query.Encode()
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("PUT=%d %s, want %d", response.Code, response.Body.String(), tc.status)
			}
			if tc.code != "" {
				assertErrorCode(t, response, tc.code)
				assertMetadataBucketEmpty(t, store, "data")
				return
			}
			response = httptest.NewRecorder()
			router.ServeHTTP(response, signedRequest(http.MethodHead, target, nil, "reader", ""))
			value, err := new(mime.WordDecoder).DecodeHeader(response.Header().Get("X-Amz-Meta-Project"))
			if response.Code != http.StatusOK || err != nil || value != tc.want {
				t.Fatalf("HEAD status=%d metadata=%q decode=%v, want %q", response.Code, value, err, tc.want)
			}
		})
	}
}

func TestObjectHandlerRejectsInvalidObjectMetadata(t *testing.T) {
	for _, version := range []string{"v2", "v4"} {
		for index, tc := range []struct {
			name, header, value, code string
		}{
			{name: "large user metadata", header: "X-Amz-Meta-Project", value: strings.Repeat("x", 2049), code: "MetadataTooLarge"},
			{name: "large representation metadata", header: "Cache-Control", value: strings.Repeat("x", 2049), code: "MetadataTooLarge"},
			{name: "empty metadata name", header: "X-Amz-Meta-", value: "value", code: "InvalidArgument"},
			{name: "metadata injection", header: "X-Amz-Meta-Project", value: "first\r\nX-Injected: yes", code: "InvalidArgument"},
		} {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				store := openTestStore(t)
				router := authenticatedTestRouter(t, store)
				payload := []byte("rejected metadata must not be committed")
				request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("http://example.com/data/20261107-1200-4000-8000-%012x", index), bytes.NewReader(payload))
				request.Header.Set(tc.header, tc.value)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, signMetadataRequest(request, version, payload))
				if response.Code != http.StatusBadRequest {
					t.Fatalf("PUT: %d %s", response.Code, response.Body.String())
				}
				assertErrorCode(t, response, tc.code)
				assertMetadataBucketEmpty(t, store, "data")
			})
		}
	}
}

func TestObjectResponseWriterClearsMetadataOnError(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			response := httptest.NewRecorder()
			for _, name := range []string{"Content-Type", "Content-Length", "Content-Disposition", "Content-Encoding", "Content-Language", "Cache-Control", "Expires", "ETag", "Last-Modified", "x-amz-meta-custom"} {
				response.Header()[name] = []string{"must not describe an XML error"}
			}
			writer := &objectResponseWriter{ResponseWriter: response, request: httptest.NewRequest(method, "/data/key", nil)}
			writer.WriteHeader(http.StatusInternalServerError)
			if response.Code != http.StatusInternalServerError || response.Header().Get("Content-Type") != "application/xml" {
				t.Fatalf("wrong error response: status=%d headers=%v", response.Code, response.Header())
			}
			for name := range response.Header() {
				if !strings.EqualFold(name, "Content-Type") {
					t.Errorf("stored metadata survived error translation: %s", name)
				}
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Error("HEAD error has a body")
			}
		})
	}
}

func signMetadataRequest(request *http.Request, version string, payload []byte) *http.Request {
	if version == "v4" {
		digest := sha256.Sum256(payload)
		request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(digest[:]))
		return signer.SignV4(*request, "writer", "secret", "", "us-east-1")
	}
	return SignV2(*request, "writer", "secret", false)
}

func assertMetadataBucketEmpty(t *testing.T, store *bucket.Store, name string) {
	t.Helper()
	b, err := store.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(b.Path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected upload changed bucket storage: entries=%v err=%v", entries, err)
	}
}
