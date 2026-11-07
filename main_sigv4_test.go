package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"glacier/s3"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/signer"
)

const (
	sigV4Writer = "v4writer"
	sigV4Reader = "v4reader"
	sigV4Secret = "v4-test-secret"
	sigV4Region = "us-east-1"
)

func TestS3V4SDKRoundTrip(t *testing.T) {
	const objectID = "20261107-1200-4000-8000-000000000401"
	type wireMetadata struct {
		hash          string
		encoding      string
		decodedLength string
		wireLength    int64
	}
	observed := make(chan wireMetadata, 1)
	server := sigV4TestServer(t, func(r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/"+objectID) {
			select {
			case observed <- wireMetadata{
				hash: r.Header.Get("X-Amz-Content-Sha256"), encoding: r.Header.Get("Content-Encoding"),
				decodedLength: r.Header.Get("X-Amz-Decoded-Content-Length"), wireLength: r.ContentLength,
			}:
			default:
			}
		}
	})
	sigV4CreateBucket(t, server, "sdk-four", "4")
	client := sigV4Client(t, server, sigV4Writer)
	reader := sigV4Client(t, server, sigV4Reader)
	// The default HTTP SDK upload signs 64 KiB chunks. This payload exercises
	// several data chunks and the terminating signed zero-length chunk.
	payload := bytes.Repeat([]byte("streamed-payload-\x00\xff"), 12000)
	if _, err := client.PutObject(t.Context(), "sdk-four", objectID, bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{}); err != nil {
		t.Fatalf("SDK signed streaming PUT: %v", err)
	}
	metadata := <-observed
	if metadata.hash != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" || metadata.encoding != "aws-chunked" ||
		metadata.decodedLength != strconv.Itoa(len(payload)) || metadata.wireLength <= int64(len(payload)) {
		t.Fatalf("SDK did not exercise signed chunk framing: %+v", metadata)
	}
	sigV4SDKGet(t, reader, "sdk-four", objectID, payload)
	info, err := reader.StatObject(t.Context(), "sdk-four", objectID, minio.StatObjectOptions{})
	if err != nil || info.Size != int64(len(payload)) {
		t.Fatalf("SDK HEAD: size=%d err=%v, want %d", info.Size, err, len(payload))
	}
	buckets, err := reader.ListBuckets(t.Context())
	if err != nil {
		t.Fatalf("SDK ListBuckets: %v", err)
	}
	listed := make(map[string]bool)
	for _, b := range buckets {
		listed[b.Name] = true
	}
	if !listed["data"] || !listed["sdk-four"] {
		t.Fatalf("SDK bucket list = %+v", buckets)
	}
	if exists, err := reader.BucketExists(t.Context(), "sdk-four"); err != nil || !exists {
		t.Fatalf("SDK bucket HEAD: exists=%v err=%v", exists, err)
	}

	tests := []struct {
		name    string
		id      string
		payload []byte
		opts    minio.PutObjectOptions
	}{
		{name: "empty signed stream", id: "20261107-1200-4000-8000-000000000402"},
		{name: "unsigned payload marker", id: "20261107-1200-4000-8000-000000000403", payload: []byte("unsigned payload"), opts: minio.PutObjectOptions{DisableContentSha256: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.PutObject(t.Context(), "sdk-four", tt.id, bytes.NewReader(tt.payload), int64(len(tt.payload)), tt.opts); err != nil {
				t.Fatalf("SDK PUT: %v", err)
			}
			sigV4SDKGet(t, reader, "sdk-four", tt.id, tt.payload)
		})
	}

	if _, err := reader.PutObject(t.Context(), "sdk-four", objectID, strings.NewReader("forbidden"), 9, minio.PutObjectOptions{}); minio.ToErrorResponse(err).StatusCode != http.StatusForbidden {
		t.Fatalf("read-only SDK PUT error=%v, want 403", err)
	}
	sigV4SDKGet(t, reader, "sdk-four", objectID, payload)
}

func TestS3V4SDKPresignedURLs(t *testing.T) {
	server := sigV4TestServer(t, nil)
	client := sigV4Client(t, server, sigV4Writer)
	reader := sigV4Client(t, server, sigV4Reader)
	const objectID = "20261107-1200-4000-8000-000000000411"
	payload := []byte("object uploaded through a presigned URL")
	putURL, err := client.PresignedPutObject(t.Context(), "data", objectID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, putURL.String(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK {
		t.Fatalf("presigned PUT: %d %s", response.StatusCode, body)
	}
	getURL, err := reader.PresignedGetObject(t.Context(), "data", objectID, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, getURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("presigned GET: %d %q", response.StatusCode, body)
	}
	headURL, err := reader.PresignedHeadObject(t.Context(), "data", objectID, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodHead, headURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK || len(body) != 0 || response.ContentLength != int64(len(payload)) {
		t.Fatalf("presigned HEAD: status=%d body=%q length=%d", response.StatusCode, body, response.ContentLength)
	}

	for _, change := range []string{"query", "date", "signature"} {
		t.Run("tampered "+change, func(t *testing.T) {
			modified := *getURL
			query := modified.Query()
			switch change {
			case "query":
				query.Set("parse", "avro")
			case "date":
				query.Set("X-Amz-Date", time.Now().Add(-24*time.Hour).UTC().Format("20060102T150405Z"))
			case "signature":
				query.Set("X-Amz-Signature", strings.Repeat("0", 64))
			}
			modified.RawQuery = query.Encode()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, modified.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, body := sigV4Do(t, server, request)
			sigV4AssertRejected(t, response, body)
		})
	}

	const deniedID = "20261107-1200-4000-8000-000000000412"
	deniedURL, err := reader.PresignedPutObject(t.Context(), "data", deniedID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err = http.NewRequestWithContext(t.Context(), http.MethodPut, deniedURL.String(), strings.NewReader("forbidden"))
	if err != nil {
		t.Fatal(err)
	}
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only presigned PUT: %d %s", response.StatusCode, body)
	}
	sigV4AssertMissing(t, reader, "data", deniedID)
}

func TestS3V4SDKChecksumTrailers(t *testing.T) {
	type wireMetadata struct {
		hash    string
		trailer string
	}
	var observedMu sync.Mutex
	observed := make(map[string]wireMetadata)
	server := sigV4TestServer(t, func(r *http.Request) {
		if r.Method == http.MethodPut {
			observedMu.Lock()
			observed[r.URL.Path] = wireMetadata{hash: r.Header.Get("X-Amz-Content-Sha256"), trailer: r.Header.Get("X-Amz-Trailer")}
			observedMu.Unlock()
		}
	})
	client := sigV4ClientSettings(t, server, sigV4Writer, true)
	reader := sigV4Client(t, server, sigV4Reader)
	checksums := []struct {
		name string
		kind minio.ChecksumType
	}{
		{name: "crc32", kind: minio.ChecksumCRC32},
		{name: "crc32c", kind: minio.ChecksumCRC32C},
		{name: "crc64nvme", kind: minio.ChecksumCRC64NVME},
		{name: "sha1", kind: minio.ChecksumSHA1},
		{name: "sha256", kind: minio.ChecksumSHA256},
	}
	payload := bytes.Repeat([]byte("trailer payload\x00\xff"), 10000)
	for mode, unsigned := range []bool{false, true} {
		name, marker := "signed", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
		if unsigned {
			name, marker = "unsigned", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
		}
		for index, checksum := range checksums {
			t.Run(name+" "+checksum.name, func(t *testing.T) {
				id := "20261107-1200-4000-8000-" + fmt.Sprintf("%012x", 0x450+mode*len(checksums)+index)
				opts := minio.PutObjectOptions{Checksum: checksum.kind, DisableContentSha256: unsigned}
				if _, err := client.PutObject(t.Context(), "data", id, bytes.NewReader(payload), int64(len(payload)), opts); err != nil {
					t.Fatalf("SDK checksum trailer PUT: %v", err)
				}
				observedMu.Lock()
				metadata := observed["/data/"+id]
				observedMu.Unlock()
				if metadata.hash != marker || metadata.trailer != "x-amz-checksum-"+checksum.name {
					t.Fatalf("SDK trailer framing = %+v, want %s with %s", metadata, marker, checksum.name)
				}
				sigV4SDKGet(t, reader, "data", id, payload)
			})
		}
	}
}

func TestS3V4SDKOperationQueryAnnotation(t *testing.T) {
	server := sigV4TestServer(t, nil)
	const objectID = "20261107-1200-4000-8000-000000000461"
	payload := []byte("object using the AWS SDK operation annotation")
	request := sigV4SignedRequest(t, server.URL+"/data/"+objectID+"?x-id=PutObject", payload, sigV4Writer)
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK {
		t.Fatalf("PUT with signed x-id: %d %s", response.StatusCode, body)
	}
	for _, presigned := range []bool{false, true} {
		name := "header signed"
		if presigned {
			name = "presigned"
		}
		t.Run(name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				server.URL+"/data/"+objectID+"?x-id=GetObject", nil)
			if err != nil {
				t.Fatal(err)
			}
			if presigned {
				request = signer.PreSignV4(*request, sigV4Reader, sigV4Secret, "", sigV4Region, 300)
			} else {
				hash := sha256.Sum256(nil)
				request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(hash[:]))
				request = signer.SignV4(*request, sigV4Reader, sigV4Secret, "", sigV4Region)
			}
			if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
				t.Fatalf("GET with signed x-id: %d %q", response.StatusCode, body)
			}
			query := request.URL.Query()
			query.Set("x-id", "PutObject")
			request.URL.RawQuery = query.Encode()
			response, body := sigV4Do(t, server, request)
			sigV4AssertRejected(t, response, body)
		})
	}
}

func TestS3V4PresignedQueryChecksum(t *testing.T) {
	server := sigV4TestServer(t, nil)
	reader := sigV4Client(t, server, sigV4Reader)
	payload := []byte("object with a checksum hoisted into its presigned URL")
	var checksum [4]byte
	binary.BigEndian.PutUint32(checksum[:], crc32.ChecksumIEEE(payload))
	digest := base64.StdEncoding.EncodeToString(checksum[:])
	for index, change := range []string{"valid", "wrong digest", "modified signed query"} {
		t.Run(change, func(t *testing.T) {
			id := "20261107-1200-4000-8000-" + fmt.Sprintf("%012x", 0x470+index)
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPut,
				server.URL+"/data/"+id, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			query := request.URL.Query()
			query.Set("x-id", "PutObject")
			query.Set("X-Amz-Checksum-Crc32", digest)
			query.Set("x-amz-sdk-checksum-algorithm", "CRC32")
			query.Set("x-amz-checksum-type", "FULL_OBJECT")
			if change == "wrong digest" {
				query.Set("X-Amz-Checksum-Crc32", "AAAAAA==")
			}
			request.URL.RawQuery = query.Encode()
			request = signer.PreSignV4(*request, sigV4Writer, sigV4Secret, "", sigV4Region, 300)
			if change == "modified signed query" {
				query = request.URL.Query()
				query.Set("X-Amz-Checksum-Crc32", "AAAAAA==")
				request.URL.RawQuery = query.Encode()
			}
			response, body := sigV4Do(t, server, request)
			wantStatus := http.StatusOK
			if change == "wrong digest" {
				wantStatus = http.StatusBadRequest
			} else if change == "modified signed query" {
				wantStatus = http.StatusForbidden
			}
			if response.StatusCode != wantStatus {
				t.Fatalf("presigned checksum PUT: status=%d body=%s, want %d", response.StatusCode, body, wantStatus)
			}
			if change == "valid" {
				sigV4SDKGet(t, reader, "data", id, payload)
				getRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
					server.URL+"/data/"+id+"?x-amz-checksum-mode=ENABLED", nil)
				if err != nil {
					t.Fatal(err)
				}
				getRequest = signer.PreSignV4(*getRequest, sigV4Reader, sigV4Secret, "", sigV4Region, 300)
				if response, body := sigV4Do(t, server, getRequest); response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
					t.Fatalf("presigned checksum-mode GET: %d %q", response.StatusCode, body)
				}
			} else {
				sigV4AssertMissing(t, reader, "data", id)
			}
		})
	}
}

func TestS3V4RejectsTamperedSignedRequests(t *testing.T) {
	server := sigV4TestServer(t, nil)
	reader := sigV4Client(t, server, sigV4Reader)
	const validID = "20261107-1200-4000-8000-000000000419"
	validPayload := []byte("a verified SHA256 payload")
	request := sigV4SignedRequest(t, server.URL+"/data/"+validID, validPayload, sigV4Writer)
	if response, body := sigV4Do(t, server, request); response.StatusCode != http.StatusOK {
		t.Fatalf("signed hashed PUT: %d %s", response.StatusCode, body)
	}
	sigV4SDKGet(t, reader, "data", validID, validPayload)
	t.Run("signed bucket count", func(t *testing.T) {
		request := sigV4SignedRequest(t, server.URL+"/tampered-count", nil, sigV4Writer)
		request.Header.Set(s3.TarFilesPerHourHeader, "4")
		request = signer.SignV4(*request, sigV4Writer, sigV4Secret, "", sigV4Region)
		request.Header.Set(s3.TarFilesPerHourHeader, "8")
		response, body := sigV4Do(t, server, request)
		sigV4AssertRejected(t, response, body)
		if exists, err := reader.BucketExists(t.Context(), "tampered-count"); err != nil || exists {
			t.Fatalf("tampered count created a bucket: exists=%v err=%v", exists, err)
		}
	})
	for i, change := range []string{"body", "date", "content type"} {
		t.Run(change, func(t *testing.T) {
			id := "20261107-1200-4000-8000-00000000042" + strconv.Itoa(i)
			request := sigV4SignedRequest(t, server.URL+"/data/"+id, []byte("original"), sigV4Writer)
			switch change {
			case "body":
				request.Body = io.NopCloser(strings.NewReader("tampered"))
			case "date":
				request.Header.Set("X-Amz-Date", time.Now().Add(-24*time.Hour).UTC().Format("20060102T150405Z"))
			case "content type":
				request.Header.Set("Content-Type", "text/html")
			}
			response, body := sigV4Do(t, server, request)
			sigV4AssertRejected(t, response, body)
			sigV4AssertMissing(t, reader, "data", id)
		})
	}
}

func TestS3V4RejectsTamperedStreamingChunks(t *testing.T) {
	server := sigV4TestServer(t, nil)
	reader := sigV4Client(t, server, sigV4Reader)
	for i, change := range []string{"data chunk", "final signature"} {
		t.Run(change, func(t *testing.T) {
			id := "20261107-1200-4000-8000-00000000043" + strconv.Itoa(i)
			payload := []byte("original streamed data")
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, server.URL+"/data/"+id, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			request = signer.StreamingSignV4(request, sigV4Writer, sigV4Secret, "", sigV4Region,
				int64(len(payload)), time.Now().UTC(), sigV4TestHasher{Hash: sha256.New()})
			encoded, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			request.Body.Close()
			switch change {
			case "data chunk":
				at := bytes.Index(encoded, payload)
				if at < 0 {
					t.Fatal("stream signer did not emit payload")
				}
				encoded[at] ^= 1
			case "final signature":
				at := bytes.LastIndex(encoded, []byte(";chunk-signature="))
				if at < 0 {
					t.Fatal("stream signer did not emit final signature")
				}
				at += len(";chunk-signature=")
				if encoded[at] == '0' {
					encoded[at] = '1'
				} else {
					encoded[at] = '0'
				}
			}
			request.Body = io.NopCloser(bytes.NewReader(encoded))
			response, body := sigV4Do(t, server, request)
			sigV4AssertRejected(t, response, body)
			sigV4AssertMissing(t, reader, "data", id)
		})
	}
}

func sigV4TestServer(t *testing.T, observe func(*http.Request)) *httptest.Server {
	t.Helper()
	t.Setenv("DATA_FOLDER", t.TempDir())
	t.Setenv("READ_TOKEN", "unrelated-raw-read-token")
	t.Setenv("WRITE_TOKEN", "unrelated-raw-write-token")
	t.Setenv("S3_READ_WRITE_USERS", sigV4Writer+"="+sigV4Secret)
	t.Setenv("S3_READ_ONLY_USERS", sigV4Reader+"="+sigV4Secret)
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	router, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if observe != nil {
			observe(r)
		}
		router.ServeHTTP(w, r)
	}))
	server.Client().Timeout = 10 * time.Second
	t.Cleanup(server.Close)
	return server
}

func sigV4Client(t *testing.T, server *httptest.Server, key string) *minio.Client {
	t.Helper()
	return sigV4ClientSettings(t, server, key, false)
}

func sigV4ClientSettings(t *testing.T, server *httptest.Server, key string, trailers bool) *minio.Client {
	t.Helper()
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4(key, sigV4Secret, ""), Secure: false,
		Region: sigV4Region, BucketLookup: minio.BucketLookupPath,
		Transport: server.Client().Transport, MaxRetries: 1, TrailingHeaders: trailers,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func sigV4CreateBucket(t *testing.T, server *httptest.Server, name, count string) {
	t.Helper()
	request := sigV4SignedRequest(t, server.URL+"/"+name, nil, sigV4Writer)
	request.Header.Set(s3.TarFilesPerHourHeader, count)
	request = signer.SignV4(*request, sigV4Writer, sigV4Secret, "", sigV4Region)
	response, body := sigV4Do(t, server, request)
	if response.StatusCode != http.StatusOK || response.Header.Get(s3.TarFilesPerHourHeader) != count {
		t.Fatalf("V4 bucket creation: status=%d count=%q body=%s", response.StatusCode, response.Header.Get(s3.TarFilesPerHourHeader), body)
	}
}

func sigV4SignedRequest(t *testing.T, target string, body []byte, key string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(hash[:]))
	request.Header.Set("Content-Type", "application/octet-stream")
	return signer.SignV4(*request, key, sigV4Secret, "", sigV4Region)
}

func sigV4Do(t *testing.T, server *httptest.Server, request *http.Request) (*http.Response, []byte) {
	t.Helper()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func sigV4SDKGet(t *testing.T, client *minio.Client, bucketName, id string, want []byte) {
	t.Helper()
	object, err := client.GetObject(t.Context(), bucketName, id, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	got, err := io.ReadAll(object)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("SDK GET %s/%s: got %d bytes, want %d; err=%v", bucketName, id, len(got), len(want), err)
	}
}

func sigV4AssertRejected(t *testing.T, response *http.Response, body []byte) {
	t.Helper()
	if response.StatusCode < 400 || response.StatusCode >= 500 {
		t.Fatalf("tampered request status=%d body=%s, want client error", response.StatusCode, body)
	}
}

func sigV4AssertMissing(t *testing.T, client *minio.Client, bucketName, id string) {
	t.Helper()
	_, err := client.StatObject(t.Context(), bucketName, id, minio.StatObjectOptions{})
	if minio.ToErrorResponse(err).StatusCode != http.StatusNotFound {
		t.Fatalf("rejected upload left an object: HEAD error=%v, want 404", err)
	}
}

type sigV4TestHasher struct{ hash.Hash }

func (sigV4TestHasher) Close() {}
