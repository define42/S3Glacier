//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/signer"
)

func TestS3ListObjectsV2SDKPagination(t *testing.T) {
	var requests atomic.Int64
	server := listingTestServer(t, false, func(r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			requests.Add(1)
		}
	})
	sigV4CreateBucket(t, server, "list-four", "4")
	sigV4CreateBucket(t, server, "list-other", "4")
	// Upload order differs from lexical order, and same-hour keys occupy
	// different shards. The long first payload is compressed by the server.
	keys := []string{
		"20261108-1200-4000-8000-000000000005",
		"20261107-1200-4000-8000-000000000001",
		"20261107-1200-4000-8000-000000000005",
		"20261106-2300-4000-8000-000000000006",
		"20261107-1200-4000-8000-000000000002",
		"20261107-1300-4000-8000-000000000004",
		"20261107-1200-4000-8000-000000000007",
	}
	payloads := make(map[string][]byte, len(keys))
	for i, key := range keys {
		payload := []byte("first content for " + key)
		if i == 1 {
			payload = bytes.Repeat([]byte("compressible original content\n"), 100)
		}
		payloads[key] = payload
		listingUpload(t, server, "list-four", "report-"+key+".txt", payload)
		if i == 2 {
			warm := listingPage(t, server, "list-four", "list-type=2")
			if len(warm.Contents) != 3 {
				t.Fatalf("initial listing contains %d objects, want 3", len(warm.Contents))
			}
		}
	}
	duplicateKey := keys[1]
	listingUpload(t, server, "list-four", duplicateKey, []byte("later duplicate"))
	listingUpload(t, server, "list-other", duplicateKey, []byte("other bucket"))
	slices.Sort(keys)

	for _, version := range []string{"V2", "V4"} {
		t.Run(version, func(t *testing.T) {
			creds := credentials.NewStaticV4(sigV4Reader, sigV4Secret, "")
			if version == "V2" {
				creds = credentials.NewStaticV2(sigV4Reader, sigV4Secret, "")
			}
			client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
				Creds: creds, Secure: false, Region: sigV4Region,
				BucketLookup: minio.BucketLookupPath, Transport: server.Client().Transport, MaxRetries: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			before := requests.Load()
			var got []string
			for object := range client.ListObjects(ctx, "list-four", minio.ListObjectsOptions{Recursive: true, MaxKeys: 2}) {
				if object.Err != nil {
					t.Fatalf("SDK ListObjects: %v", object.Err)
				}
				got = append(got, object.Key)
				payload, exists := payloads[object.Key]
				if !exists || object.Size != int64(len(payload)) {
					t.Fatalf("listed object = %+v; want canonical key and original size", object)
				}
				wantTime, err := time.Parse("20060102", object.Key[:8])
				if err != nil || !object.LastModified.Equal(wantTime) || object.StorageClass != "STANDARD" || object.Owner.ID == "" {
					t.Fatalf("listed metadata = %+v, want date %v, STANDARD and owner; error=%v", object, wantTime, err)
				}
			}
			wantPages := int64((len(keys) + 1) / 2)
			if !slices.Equal(got, keys) || requests.Load()-before < wantPages {
				t.Fatalf("SDK pagination returned %v in %d requests, want %v across at least %d pages", got, requests.Load()-before, keys, wantPages)
			}
			info, err := client.StatObject(ctx, "list-four", duplicateKey, minio.StatObjectOptions{})
			if err != nil || info.Size != int64(len(payloads[duplicateKey])) {
				t.Fatalf("first duplicate metadata differs from HEAD: %+v, %v", info, err)
			}
			sigV4SDKGet(t, client, "list-four", duplicateKey, payloads[duplicateKey])
		})
	}
	other := listingPage(t, server, "list-other", "list-type=2")
	if len(other.Contents) != 1 || other.Contents[0].Key != duplicateKey || other.Contents[0].Size != int64(len("other bucket")) {
		t.Fatalf("other bucket listing = %+v", other)
	}
}

func TestS3ListObjectsV2QuerySemantics(t *testing.T) {
	server := listingTestServer(t, false, nil)
	sigV4CreateBucket(t, server, "list-query", "4")
	sigV4CreateBucket(t, server, "list-empty", "4")
	keys := []string{
		"20260101-1100-4000-8000-000000000001",
		"20260101-1200-4000-8000-000000000002",
		"20260102-1200-4000-8000-000000000003",
		"20260103-1200-4000-8000-000000000004",
	}
	for _, key := range slices.Backward(keys) {
		listingUpload(t, server, "list-query", key, []byte(key))
	}

	t.Run("prefix and continuation", func(t *testing.T) {
		query := url.Values{"list-type": {"2"}, "prefix": {"202601"}, "start-after": {keys[0]}, "max-keys": {"1"}}
		first := listingPage(t, server, "list-query", query.Encode())
		if first.Name != "list-query" || first.Prefix != "202601" || first.StartAfter != keys[0] ||
			first.KeyCount != 1 || first.MaxKeys != 1 || !first.IsTruncated || first.NextContinuationToken == "" ||
			len(first.Contents) != 1 || first.Contents[0].Key != keys[1] {
			t.Fatalf("first page = %+v", first)
		}
		query.Set("continuation-token", first.NextContinuationToken)
		query.Set("start-after", keys[3]) // The continuation token takes precedence.
		query.Set("max-keys", "2")
		second := listingPage(t, server, "list-query", query.Encode())
		if second.IsTruncated || second.KeyCount != 2 || second.ContinuationToken != first.NextContinuationToken ||
			!slices.Equal(listingKeys(second), keys[2:]) {
			t.Fatalf("continuation page = %+v", second)
		}
		query.Set("prefix", "20260102")
		listingExpectError(t, server, "list-query", query.Encode(), http.StatusBadRequest, "InvalidArgument")
		query.Set("prefix", "202601")
		listingExpectError(t, server, "list-empty", query.Encode(), http.StatusBadRequest, "InvalidArgument")
	})

	t.Run("delimiter groups paginate once", func(t *testing.T) {
		query := url.Values{"list-type": {"2"}, "prefix": {"2026"}, "delimiter": {"-"}, "max-keys": {"1"}}
		var got []string
		for range 4 {
			page := listingPage(t, server, "list-query", query.Encode())
			if len(page.Contents) != 0 || page.KeyCount != 1 || len(page.CommonPrefixes) != 1 {
				t.Fatalf("delimiter page = %+v", page)
			}
			got = append(got, page.CommonPrefixes[0].Prefix)
			if !page.IsTruncated {
				break
			}
			if page.NextContinuationToken == "" || page.NextContinuationToken == query.Get("continuation-token") {
				t.Fatalf("delimiter cursor did not advance: %+v", page)
			}
			query.Set("continuation-token", page.NextContinuationToken)
		}
		if !slices.Equal(got, []string{"20260101-", "20260102-", "20260103-"}) {
			t.Fatalf("delimiter groups = %v", got)
		}
		page := listingPage(t, server, "list-query", "list-type=2&delimiter=-&start-after="+keys[1])
		if len(page.CommonPrefixes) != 2 || page.CommonPrefixes[0].Prefix != "20260102-" {
			t.Fatalf("start-after did not filter common prefixes: %+v", page)
		}
	})

	t.Run("encoding and optional owner", func(t *testing.T) {
		query := url.Values{"list-type": {"2"}, "encoding-type": {"url"}, "prefix": {"space /+"}, "delimiter": {"/"}, "start-after": {"space /+"}}
		page := listingPage(t, server, "list-query", query.Encode())
		if page.EncodingType != "url" || page.Prefix != "space%20%2F%2B" || page.StartAfter != page.Prefix || page.Delimiter != "%2F" {
			t.Fatalf("URL encoded response = %+v", page)
		}
		page = listingPage(t, server, "list-query", "list-type=2&max-keys=1")
		if len(page.Contents) != 1 || page.Contents[0].Owner != nil {
			t.Fatalf("owner included without fetch-owner: %+v", page)
		}
		page = listingPage(t, server, "list-query", "list-type=2&max-keys=1&fetch-owner=true")
		if len(page.Contents) != 1 || page.Contents[0].Owner == nil || page.Contents[0].Owner.ID == "" {
			t.Fatalf("fetch-owner omitted owner: %+v", page)
		}
	})

	for _, tc := range []struct{ name, bucket, query string }{
		{name: "empty bucket", bucket: "list-empty", query: "list-type=2"},
		{name: "missing prefix", bucket: "list-query", query: "list-type=2&prefix=missing"},
		{name: "zero page size", bucket: "list-query", query: "list-type=2&max-keys=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := listingPage(t, server, tc.bucket, tc.query)
			if page.KeyCount != 0 || page.IsTruncated || len(page.Contents) != 0 || page.NextContinuationToken != "" {
				t.Fatalf("empty page = %+v", page)
			}
		})
	}
	for _, tc := range []struct{ name, query string }{
		{name: "negative page size", query: "max-keys=-1"},
		{name: "oversized page", query: "max-keys=1001"},
		{name: "nonnumeric page size", query: "max-keys=abc"},
		{name: "duplicate parameter", query: "max-keys=1&max-keys=2"},
		{name: "malformed token", query: "continuation-token=not-a-valid-token"},
		{name: "unsupported encoding", query: "encoding-type=base64"},
		{name: "invalid fetch owner", query: "fetch-owner=maybe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listingExpectError(t, server, "list-query", "list-type=2&"+tc.query, http.StatusBadRequest, "InvalidArgument")
		})
	}
	listingExpectError(t, server, "absent-bucket", "list-type=2", http.StatusNotFound, "NoSuchBucket")
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/list-query?list-type=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := sigV4Do(t, server, request)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned listing returned %d", response.StatusCode)
	}
}

func TestS3ListObjectsV2ExtendedRetention(t *testing.T) {
	server := listingTestServer(t, true, nil)
	// The lexical first key lives in December, after the second key's November
	// folder. Listing must not treat physical folder order as key order.
	keys := []string{
		"20261107-1081-4000-8000-000000000001",
		"20261108-1000-4000-8000-000000000002",
	}
	for _, key := range keys {
		listingUpload(t, server, "data", key, []byte(key))
	}
	archives, err := filepath.Glob(filepath.Join(os.Getenv("DATA_FOLDER"), "buckets", "data", "2026", "12", "07", "10", "*.tar"))
	if err != nil || len(archives) != 1 {
		t.Fatalf("fixture did not use extended retention: archives=%v error=%v", archives, err)
	}
	page := listingPage(t, server, "data", "list-type=2&prefix=202611&max-keys=1")
	if !slices.Equal(listingKeys(page), keys[:1]) || !page.IsTruncated {
		t.Fatalf("extended first page = %+v", page)
	}
	query := url.Values{"list-type": {"2"}, "prefix": {"202611"}, "max-keys": {"1"}, "continuation-token": {page.NextContinuationToken}}
	page = listingPage(t, server, "data", query.Encode())
	if !slices.Equal(listingKeys(page), keys[1:]) || page.IsTruncated {
		t.Fatalf("extended continuation = %+v", page)
	}
}

type listingResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	Name                  string
	Prefix                string
	Delimiter             string
	EncodingType          string
	StartAfter            string
	KeyCount              int
	MaxKeys               int
	IsTruncated           bool
	ContinuationToken     string
	NextContinuationToken string
	Contents              []struct {
		Key   string
		Size  int64
		Owner *struct{ ID string }
	}
	CommonPrefixes []struct{ Prefix string }
}

func listingTestServer(t *testing.T, extend bool, observe func(*http.Request)) *httptest.Server {
	t.Helper()
	t.Setenv("DATA_FOLDER", t.TempDir())
	t.Setenv("READ_TOKEN", "unrelated-raw-read-token")
	t.Setenv("WRITE_TOKEN", "unrelated-raw-write-token")
	t.Setenv("S3_READ_WRITE_USERS", sigV4Writer+"="+sigV4Secret)
	t.Setenv("S3_READ_ONLY_USERS", sigV4Reader+"="+sigV4Secret)
	t.Setenv("EXTEND_LIFE_SUPPORT", "false")
	if extend {
		t.Setenv("EXTEND_LIFE_SUPPORT", "true")
	}
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
	server.Client().Timeout = 5 * time.Second
	t.Cleanup(server.Close)
	return server
}

func listingUpload(t *testing.T, server *httptest.Server, bucketName, key string, payload []byte) {
	t.Helper()
	request := sigV4SignedRequest(t, server.URL+"/"+bucketName+"/"+url.PathEscape(key), payload, sigV4Writer)
	response, body := sigV4Do(t, server, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upload %s/%s: status=%d body=%s", bucketName, key, response.StatusCode, body)
	}
}

func listingRequest(t *testing.T, server *httptest.Server, bucketName, query string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/"+bucketName+"?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	request = signer.SignV4(*request, sigV4Reader, sigV4Secret, "", sigV4Region)
	return sigV4Do(t, server, request)
}

func listingPage(t *testing.T, server *httptest.Server, bucketName, query string) listingResult {
	t.Helper()
	response, body := listingRequest(t, server, bucketName, query)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list %s?%s: status=%d body=%s", bucketName, query, response.StatusCode, body)
	}
	var page listingResult
	if err := xml.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode listing: %v; body=%s", err, body)
	}
	if page.XMLName.Space != "http://s3.amazonaws.com/doc/2006-03-01/" {
		t.Fatalf("listing XML namespace = %q", page.XMLName.Space)
	}
	return page
}

func listingKeys(page listingResult) []string {
	keys := make([]string, 0, len(page.Contents))
	for _, object := range page.Contents {
		keys = append(keys, object.Key)
	}
	return keys
}

func listingExpectError(t *testing.T, server *httptest.Server, bucketName, query string, status int, code string) {
	t.Helper()
	response, body := listingRequest(t, server, bucketName, query)
	var failure struct{ Code string }
	if err := xml.Unmarshal(body, &failure); err != nil || response.StatusCode != status || failure.Code != code {
		t.Fatalf("list error status=%d body=%s, want %d %s; decode error=%v", response.StatusCode, body, status, code, err)
	}
}
