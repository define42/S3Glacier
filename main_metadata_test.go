//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"glacier/archive"
	"glacier/bucket"
	"glacier/shared"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestS3ObjectMetadataSDKRoundTrip(t *testing.T) {
	for _, version := range []string{"V2", "V4"} {
		t.Run(version, func(t *testing.T) {
			server := sigV4TestServer(t, nil)
			client := metadataClient(t, server, version)
			const id = "20261107-1200-4000-8000-000000000701"
			payload := bytes.Repeat([]byte("original compressed archive content\n"), 50)
			expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
			opts := minio.PutObjectOptions{
				UserMetadata: map[string]string{"Department": "Research", "OWNER": "Zoë 東京", "empty": ""},
				ContentType:  "application/x-s3glacier-test", ContentDisposition: `attachment; filename="original.bin"`,
				ContentEncoding: "identity", ContentLanguage: "en", CacheControl: "private, max-age=60", Expires: expires,
			}
			put, err := client.PutObject(t.Context(), "data", id, bytes.NewReader(payload), int64(len(payload)), opts)
			if err != nil {
				t.Fatalf("SDK PUT metadata: %v", err)
			}
			hash := md5.Sum(payload)
			etag := hex.EncodeToString(hash[:])
			if put.ETag != etag {
				t.Fatalf("PUT ETag = %q, want %q", put.ETag, etag)
			}
			metadataAssertSDKObject(t, client, id, payload, opts, etag)
			metadataAssertListingETag(t, client, id, etag)
			// The listing cache and object response must retain the first entry's
			// bytes and metadata after a different upload using the same UUID.
			if _, err := client.PutObject(t.Context(), "data", id, strings.NewReader("duplicate"), 9, minio.PutObjectOptions{
				UserMetadata: map[string]string{"Department": "Later"}, ContentType: "text/duplicate",
			}); err != nil {
				t.Fatalf("duplicate SDK PUT: %v", err)
			}
			metadataAssertSDKObject(t, client, id, payload, opts, etag)
			metadataAssertListingETag(t, client, id, etag)

			headers := metadataArchiveHeaders(t, "data", 256, id)
			if len(headers) != 2 || headers[0].Mode != 1 || headers[0].Uid != len(payload) {
				t.Fatalf("stored entries = %+v, want two entries with compressed first object", headers)
			}
			pax := headers[0].PAXRecords
			want := metadataExpectedHeaders(opts)
			for key, value := range want {
				if pax["S3Glacier.http."+strings.ToLower(key)] != value {
					t.Fatalf("PAX representation %s = %q, want %q", key, pax["S3Glacier.http."+strings.ToLower(key)], value)
				}
			}
			for key, value := range opts.UserMetadata {
				stored, exists := pax["S3Glacier.meta."+strings.ToLower(key)]
				if !exists || stored != value {
					t.Fatalf("flat PAX metadata %s = %q (present=%v), want %q", key, stored, exists, value)
				}
			}
			digest := sha256.Sum256(payload)
			if pax["S3Glacier.etag"] != etag || pax[archive.SHA256Key] != hex.EncodeToString(digest[:]) {
				t.Fatalf("stored checksums = %v", pax)
			}
			for key, value := range pax {
				if strings.HasPrefix(key, "S3Glacier.") && key != archive.SHA256Key && key != "S3Glacier.etag" &&
					!strings.HasPrefix(key, "S3Glacier.meta.") && !strings.HasPrefix(key, "S3Glacier.http.") {
					t.Fatalf("unexpected metadata container %q; metadata must use flat PAX records", key)
				}
				if strings.Contains(value, sigV4Secret) || strings.Contains(value, "AWS4-HMAC") || strings.Contains(value, "aws-chunked") {
					t.Fatalf("transport/authentication data persisted in PAX %q", key)
				}
			}
			for _, key := range []string{"authorization", "content-length", "transfer-encoding", "x-amz-date", "x-amz-content-sha256", "x-amz-decoded-content-length"} {
				if _, exists := pax["S3Glacier.http."+key]; exists {
					t.Fatalf("transport header %s was persisted", key)
				}
			}

			server = metadataRestartServer(t, server)
			metadataAssertSDKObject(t, metadataClient(t, server, version), id, payload, opts, etag)
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				request, err := http.NewRequestWithContext(t.Context(), method, server.URL+"/get/"+id, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer unrelated-raw-read-token")
				response, body := sigV4Do(t, server, request)
				if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != `"`+etag+`"` ||
					response.Header.Get("X-Amz-Meta-Department") != "Research" || response.Header.Get("Content-Type") != opts.ContentType {
					t.Fatalf("HTTP %s metadata after restart: %d %v", method, response.StatusCode, response.Header)
				}
				if method == http.MethodGet && !bytes.Equal(body, payload) || method == http.MethodHead && len(body) != 0 {
					t.Fatalf("HTTP %s body after restart has %d bytes", method, len(body))
				}
			}
		})
	}
}

func TestS3ObjectMetadataStreamingGZIP(t *testing.T) {
	type wireHeaders struct{ encoding, hash string }
	observed := make(chan wireHeaders, 1)
	server := sigV4TestServer(t, func(r *http.Request) {
		if r.Method == http.MethodPut {
			select {
			case observed <- wireHeaders{r.Header.Get("Content-Encoding"), r.Header.Get("X-Amz-Content-Sha256")}:
			default:
			}
		}
	})
	client := metadataClient(t, server, "V4")
	const id = "20261107-1200-4000-8000-000000000702"
	plain := make([]byte, 2048)
	for i := range plain {
		plain[i] = byte(i * 31)
	}
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	payload := compressed.Bytes()
	if len(payload) <= 100 {
		t.Fatal("fixture must also exercise archive-level compression")
	}
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", ContentEncoding: "gzip", UserMetadata: map[string]string{"kind": "encoded-object"}}
	if _, err := client.PutObject(t.Context(), "data", id, bytes.NewReader(payload), int64(len(payload)), opts); err != nil {
		t.Fatalf("SDK gzip streaming PUT: %v", err)
	}
	wire := <-observed
	if !strings.Contains(wire.encoding, "aws-chunked") || !strings.Contains(wire.encoding, "gzip") || wire.hash != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		t.Fatalf("fixture did not exercise signed streaming plus gzip: %+v", wire)
	}
	hash := md5.Sum(payload)
	metadataAssertSDKObject(t, client, id, payload, opts, hex.EncodeToString(hash[:]))
	headers := metadataArchiveHeaders(t, "data", 256, id)
	if len(headers) != 1 || headers[0].Mode != 1 || headers[0].Uid != len(payload) || headers[0].PAXRecords["S3Glacier.http.content-encoding"] != "gzip" {
		t.Fatalf("transport and application compression were confused: %+v", headers)
	}
}

func TestS3ObjectMetadataPresignedQuery(t *testing.T) {
	server := sigV4TestServer(t, nil)
	client := sigV4Client(t, server, sigV4Writer)
	const id = "20261107-1200-4000-8000-000000000703"
	metadata := url.Values{"x-amz-meta-source": {"signed-query"}, "x-amz-meta-label": {"A+B / C"}}
	u, err := client.Presign(t.Context(), http.MethodPut, "data", id, time.Minute, metadata)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, u.String(), strings.NewReader("presigned object"))
	if err != nil {
		t.Fatal(err)
	}
	response, body := sigV4Do(t, server, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("presigned metadata PUT: %d %s", response.StatusCode, body)
	}
	info, err := client.StatObject(t.Context(), "data", id, minio.StatObjectOptions{})
	if err != nil || info.Metadata.Get("X-Amz-Meta-Source") != "signed-query" || info.Metadata.Get("X-Amz-Meta-Label") != "A+B / C" {
		t.Fatalf("presigned metadata result = %+v, error=%v", info, err)
	}
	query := u.Query()
	query.Set("x-amz-meta-source", "tampered")
	u.RawQuery = query.Encode()
	request, err = http.NewRequestWithContext(t.Context(), http.MethodPut, u.String(), strings.NewReader("tampered"))
	if err != nil {
		t.Fatal(err)
	}
	response, body = sigV4Do(t, server, request)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered signed metadata accepted: %d %s", response.StatusCode, body)
	}
}

func TestS3ObjectMetadataRejectedBeforeArchiveMutation(t *testing.T) {
	server := sigV4TestServer(t, nil)
	sigV4CreateBucket(t, server, "meta-one", "1")
	sigV4CreateBucket(t, server, "meta-empty", "1")
	const existing = "20261107-1200-4000-8000-000000000711"
	const rejected = "20261107-1200-4000-8000-000000000712"
	request := sigV4SignedRequest(t, server.URL+"/meta-one/"+existing, []byte("healthy"), sigV4Writer)
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK {
		t.Fatalf("initial upload: %d %s", response.StatusCode, body)
	}
	path := metadataArchivePath(t, "meta-one", 1, existing)
	before := snapshotHTTPArchive(t, path)
	for _, tc := range []struct {
		name, key, value, code string
	}{
		{name: "user metadata too large", key: "X-Amz-Meta-Large", value: strings.Repeat("x", 2049), code: "MetadataTooLarge"},
		{name: "representation too large", key: "Content-Disposition", value: strings.Repeat("x", 2049), code: "MetadataTooLarge"},
		{name: "empty metadata name", key: "X-Amz-Meta-", value: "invalid", code: "InvalidArgument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, bucketName := range []string{"meta-one", "meta-empty"} {
				request := sigV4SignedRequest(t, server.URL+"/"+bucketName+"/"+rejected, []byte("rejected"), sigV4Writer)
				request.Header.Set(tc.key, tc.value)
				request = signer.SignV4(*request, sigV4Writer, sigV4Secret, "", sigV4Region)
				response, body := sigV4Do(t, server, request)
				var failure struct{ Code string }
				if err := xml.Unmarshal(body, &failure); err != nil || response.StatusCode != http.StatusBadRequest || failure.Code != tc.code {
					t.Fatalf("invalid metadata response = %d %s; want 400 %s; decode=%v", response.StatusCode, body, tc.code, err)
				}
			}
		})
	}
	if after := snapshotHTTPArchive(t, path); !maps.Equal(before, after) {
		t.Fatal("rejected metadata changed an existing TAR or checkpoint")
	}
	entries, err := os.ReadDir(filepath.Join(os.Getenv("DATA_FOLDER"), "buckets", "meta-empty"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected metadata created archive files: entries=%v error=%v", entries, err)
	}
	sigV4SDKGet(t, sigV4Client(t, server, sigV4Reader), "meta-one", existing, []byte("healthy"))
	request = sigV4SignedRequest(t, server.URL+"/meta-one/"+rejected, []byte("valid after rejection"), sigV4Writer)
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK {
		t.Fatalf("invalid metadata quarantined the archive: %d %s", response.StatusCode, body)
	}
}

func TestHTTPMultipartDoesNotPersistRequestMetadata(t *testing.T) {
	server := sigV4TestServer(t, nil)
	const id = "20261107-1200-4000-8000-000000000721"
	request := retryMultipartRequest(t, id, []byte("HTTP multipart content"))
	request.URL.Scheme = "http"
	request.URL.Host = strings.TrimPrefix(server.URL, "http://")
	request.RequestURI = ""
	request.Header.Set("Authorization", "Bearer unrelated-raw-write-token")
	request.Header.Set("X-Amz-Meta-Transport", "must-not-persist")
	request.Header.Set("Cache-Control", "request-cache-control")
	response, body := sigV4Do(t, server, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("multipart upload: %d %s", response.StatusCode, body)
	}
	headers := metadataArchiveHeaders(t, "data", 256, id)
	if len(headers) != 1 {
		t.Fatalf("stored multipart entries = %d", len(headers))
	}
	for key, value := range headers[0].PAXRecords {
		if strings.HasPrefix(key, "S3Glacier.meta.") || strings.HasPrefix(key, "S3Glacier.http.") || strings.Contains(value, "multipart/form-data") {
			t.Fatalf("multipart request metadata was stored: %s=%s", key, value)
		}
	}
}

func metadataClient(t *testing.T, server *httptest.Server, version string) *minio.Client {
	t.Helper()
	creds := credentials.NewStaticV4(sigV4Writer, sigV4Secret, "")
	if version == "V2" {
		creds = credentials.NewStaticV2(sigV4Writer, sigV4Secret, "")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true // Assert the stored representation bytes, not Go's transparent decoding.
	transport.ResponseHeaderTimeout = 5 * time.Second
	t.Cleanup(transport.CloseIdleConnections)
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds: creds, Secure: false, Region: sigV4Region, BucketLookup: minio.BucketLookupPath, Transport: transport, MaxRetries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func metadataExpectedHeaders(opts minio.PutObjectOptions) map[string]string {
	headers := map[string]string{"Content-Type": opts.ContentType}
	for key, value := range map[string]string{
		"Content-Disposition": opts.ContentDisposition, "Content-Encoding": opts.ContentEncoding,
		"Content-Language": opts.ContentLanguage, "Cache-Control": opts.CacheControl,
	} {
		if value != "" {
			headers[key] = value
		}
	}
	if !opts.Expires.IsZero() {
		headers["Expires"] = opts.Expires.UTC().Format(http.TimeFormat)
	}
	return headers
}

func metadataAssertSDKObject(t *testing.T, client *minio.Client, id string, payload []byte, opts minio.PutObjectOptions, etag string) {
	t.Helper()
	stat, err := client.StatObject(t.Context(), "data", id, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("SDK HEAD metadata: %v", err)
	}
	if stat.Size != int64(len(payload)) {
		t.Fatalf("SDK HEAD size = %d, want %d", stat.Size, len(payload))
	}
	object, err := client.GetObject(t.Context(), "data", id, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	body, err := io.ReadAll(object)
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("SDK GET bytes = %d, want %d; error=%v", len(body), len(payload), err)
	}
	got, err := object.Stat()
	if err != nil {
		t.Fatalf("SDK GET metadata: %v", err)
	}
	for _, info := range []minio.ObjectInfo{stat, got} {
		// Object.Stat reports the remaining size after reading. The original
		// representation size remains available in the GET response headers.
		if info.ETag != etag || info.Headers.Get("ETag") != `"`+etag+`"` || info.Headers.Get("Content-Length") != strconv.Itoa(len(payload)) {
			t.Fatalf("GET/HEAD metadata size=%d etag=%q headers=%v", info.Size, info.ETag, info.Headers)
		}
		for key, value := range metadataExpectedHeaders(opts) {
			if info.Headers.Get(key) != value {
				t.Fatalf("GET/HEAD %s = %q, want %q", key, info.Headers.Get(key), value)
			}
		}
		for key, value := range opts.UserMetadata {
			values, exists := info.Metadata[http.CanonicalHeaderKey("X-Amz-Meta-"+key)]
			if !exists || len(values) != 1 || values[0] != value {
				t.Fatalf("SDK metadata %s = %v (present=%v), want %q", key, values, exists, value)
			}
		}
	}
}

func metadataAssertListingETag(t *testing.T, client *minio.Client, id, etag string) {
	t.Helper()
	count := 0
	for object := range client.ListObjects(t.Context(), "data", minio.ListObjectsOptions{Prefix: id, Recursive: true}) {
		if object.Err != nil || object.Key != id || object.ETag != etag || len(object.UserMetadata) != 0 {
			t.Fatalf("listed first-entry ETag = %+v, want %q without custom metadata", object, etag)
		}
		count++
	}
	if count != 1 {
		t.Fatalf("listing contains %d entries for one UUID", count)
	}
}

func metadataArchivePath(t *testing.T, bucketName string, count int, id string) string {
	t.Helper()
	b := bucket.Bucket{Name: bucketName, TarFilesPerHour: count, Path: filepath.Join(os.Getenv("DATA_FOLDER"), "buckets", bucketName)}
	path, _, err := shared.GetBucketContainerFile(b, id)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func metadataArchiveHeaders(t *testing.T, bucketName string, count int, id string) []*tar.Header {
	t.Helper()
	r, err := archive.Default.Open(t.Context(), metadataArchivePath(t, bucketName, count, id))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var headers []*tar.Header
	reader := tar.NewReader(r)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return headers
		}
		if err != nil {
			t.Fatal(err)
		}
		if !archive.IsInternalEntry(header) && header.Name == id {
			headers = append(headers, header)
		}
	}
}

func metadataRestartServer(t *testing.T, server *httptest.Server) *httptest.Server {
	t.Helper()
	server.Close()
	previous := archive.Default
	archive.Default = archive.NewStore()
	t.Cleanup(func() { archive.Default = previous })
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	restarted := httptest.NewServer(router)
	restarted.Client().Timeout = 5 * time.Second
	t.Cleanup(restarted.Close)
	return restarted
}
