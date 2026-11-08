package s3

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
)

func TestParseListQuery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, query string
		want        listQuery
		code        string
	}{
		{name: "defaults", query: "list-type=2", want: listQuery{maxKeys: 1000}},
		{name: "zero page", query: "list-type=2&max-keys=0", want: listQuery{maxKeys: 0}},
		{name: "literal prefix", query: "list-type=2&prefix=not-a-uuid%2F&delimiter=--&start-after=arbitrary&fetch-owner=true&encoding-type=url&max-keys=7",
			want: listQuery{prefix: "not-a-uuid/", delimiter: "--", after: "arbitrary", startAfter: "arbitrary", fetchOwner: true, encodeURL: true, maxKeys: 7}},
		{name: "encoded control character", query: "list-type=2&prefix=%00&encoding-type=url", want: listQuery{prefix: "\x00", encodeURL: true, maxKeys: 1000}},
		{name: "negative count", query: "list-type=2&max-keys=-1", code: "InvalidArgument"},
		{name: "too many keys", query: "list-type=2&max-keys=1001", code: "InvalidArgument"},
		{name: "count overflow", query: "list-type=2&max-keys=99999999999999999999", code: "InvalidArgument"},
		{name: "noninteger count", query: "list-type=2&max-keys=1.5", code: "InvalidArgument"},
		{name: "empty count", query: "list-type=2&max-keys=", code: "InvalidArgument"},
		{name: "duplicate prefix", query: "list-type=2&prefix=a&prefix=b", code: "InvalidArgument"},
		{name: "duplicate version", query: "list-type=2&list-type=2", code: "InvalidArgument"},
		{name: "unsupported version", query: "list-type=1", code: "InvalidArgument"},
		{name: "unknown parameter", query: "list-type=2&versions=", code: "NotImplemented"},
		{name: "unsupported encoding", query: "list-type=2&encoding-type=base64", code: "InvalidArgument"},
		{name: "invalid owner flag", query: "list-type=2&fetch-owner=yes", code: "InvalidArgument"},
		{name: "empty token", query: "list-type=2&continuation-token=", code: "InvalidArgument"},
		{name: "XML control character", query: "list-type=2&prefix=%00", code: "InvalidArgument"},
		{name: "invalid UTF8", query: "list-type=2&prefix=%ff&encoding-type=url", code: "InvalidArgument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseListQuery(values)
			if tc.code != "" {
				var argument *listQueryError
				if !errors.As(err, &argument) || argument.code != tc.code {
					t.Fatalf("error=%v, want %s", err, tc.code)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("query=%+v err=%v, want %+v", got, err, tc.want)
			}
		})
	}
}

func TestBucketHandlerListObjectsV2Errors(t *testing.T) {
	store := openTestStore(t)
	for _, tc := range []struct {
		name, bucket, query string
		user                S3User
		status              int
		code                string
	}{
		{name: "empty bucket", bucket: "data", query: "list-type=2", user: S3User{Read: true}, status: 200},
		{name: "missing bucket", bucket: "missing", query: "list-type=2", user: S3User{Read: true}, status: 404, code: "NoSuchBucket"},
		{name: "read permission required", bucket: "data", query: "list-type=2", user: S3User{Write: true}, status: 403, code: "AccessDenied"},
		{name: "malformed escape", bucket: "data", query: "list-type=2&prefix=%zz", user: S3User{Read: true}, status: 400, code: "InvalidArgument"},
		{name: "malformed separator", bucket: "data", query: "list-type=2&prefix=a;b", user: S3User{Read: true}, status: 400, code: "InvalidArgument"},
		{name: "V1 remains unsupported", bucket: "data", query: "prefix=2026", user: S3User{Read: true}, status: 501, code: "NotImplemented"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/"+tc.bucket, nil)
			request.URL.RawQuery = tc.query
			request = mux.SetURLVars(request, map[string]string{"bucket": tc.bucket})
			response := httptest.NewRecorder()
			BucketHandler(store)(response, request, tc.user)
			if response.Code != tc.status {
				t.Fatalf("status=%d, want %d: %s", response.Code, tc.status, response.Body.String())
			}
			if tc.code != "" {
				assertErrorCode(t, response, tc.code)
			}
		})
	}
}
