package s3

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"
)

// These fixed signatures are published AWS test vectors, independent of our signer.
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html
func TestVerifyV4AWSVectors(t *testing.T) {
	registerV4TestUser(t, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name, method, target, body, hash, signed, signature string
		additional                                          http.Header
	}{
		{
			name: "get object range", method: "GET", target: "https://examplebucket.s3.amazonaws.com/test.txt",
			hash: v4EmptyHash, signed: "host;range;x-amz-content-sha256;x-amz-date",
			signature:  "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
			additional: http.Header{"Range": []string{"bytes=0-9"}},
		},
		{
			name: "put escaped object name", method: "PUT", target: "https://examplebucket.s3.amazonaws.com/test%24file.text",
			body: "Welcome to Amazon S3.", hash: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			signed:     "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
			signature:  "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
			additional: http.Header{"Date": []string{"Fri, 24 May 2013 00:00:00 GMT"}, "X-Amz-Storage-Class": []string{"REDUCED_REDUNDANCY"}},
		},
		{
			name: "empty subresource query", method: "GET", target: "https://examplebucket.s3.amazonaws.com/?lifecycle",
			hash: v4EmptyHash, signed: "host;x-amz-content-sha256;x-amz-date",
			signature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "sorted query", method: "GET", target: "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			hash: v4EmptyHash, signed: "host;x-amz-content-sha256;x-amz-date",
			signature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
		{
			name: "presigned URL", method: "GET",
			target: "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := newV4TestRequest(t, tc.method, tc.target, tc.body)
			if tc.signature != "" {
				request.Header = tc.additional.Clone()
				if request.Header == nil {
					request.Header = make(http.Header)
				}
				request.Header.Set("X-Amz-Date", "20130524T000000Z")
				request.Header.Set("X-Amz-Content-Sha256", tc.hash)
				request.Header.Set(Authorization, signV4Algorithm+" Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders="+tc.signed+",Signature="+tc.signature)
			}
			user, info, err := verifyV4(request, now)
			if err != nil {
				t.Fatalf("AWS signature rejected: %v", err)
			}
			if !user.Read || !user.Write || info.Scope != "20130524/us-east-1/s3/aws4_request" || len(info.SigningKey) != sha256.Size {
				t.Fatalf("unexpected verified identity/info: %+v %+v", user, info)
			}
		})
	}
}

func TestVerifyV4MinIOSignatures(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	for _, presigned := range []bool{false, true} {
		name := "header"
		if presigned {
			name = "presigned"
		}
		t.Run(name, func(t *testing.T) {
			request := newV4TestRequest(t, "PUT", "https://archive.example:9443/my-bucket//a/../snow%E2%98%83%20%2B%25?prefix=snow%20%2B&acl", "payload")
			request.Header.Set(TarFilesPerHourHeader, "4")
			request.Header.Set("Content-Type", "text/plain")
			if presigned {
				request = signer.PreSignV4(*request, "writer", "secret", "", "eu-west-1", 60)
			} else {
				request = signer.SignV4(*request, "writer", "secret", "", "eu-west-1")
			}
			originalQuery := request.URL.RawQuery
			_, info, err := verifyV4(request, time.Now())
			if err != nil {
				t.Fatalf("MinIO signature rejected: %v", err)
			}
			if info.Presigned != presigned || info.PayloadHash != unsignedPayload || request.URL.RawQuery != originalQuery {
				t.Fatalf("payload/query altered: %+v %q", info, request.URL.RawQuery)
			}
			request.Host = "archive.example:9444"
			_, _, err = verifyV4(request, time.Now())
			assertV4Failure(t, err, "SignatureDoesNotMatch")
		})
	}
}

func TestVerifyV4HeaderRejections(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	cases := []struct {
		name, code string
		mutate     func(*http.Request)
	}{
		{name: "tampered signed metadata", code: "SignatureDoesNotMatch", mutate: func(r *http.Request) { r.Header.Set(TarFilesPerHourHeader, "8") }},
		{name: "tampered object path", code: "SignatureDoesNotMatch", mutate: func(r *http.Request) { r.URL.Path += "changed" }},
		{name: "tampered query", code: "SignatureDoesNotMatch", mutate: func(r *http.Request) { r.URL.RawQuery = "location=changed" }},
		{name: "tampered payload hash", code: "SignatureDoesNotMatch", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", v4EmptyHash) }},
		{name: "missing signed header", code: "AccessDenied", mutate: func(r *http.Request) { r.Header.Del(TarFilesPerHourHeader) }},
		{name: "unsigned x amz header", code: "AccessDenied", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Meta-Unsigned", "value") }},
		{name: "unsigned content md5", code: "AccessDenied", mutate: func(r *http.Request) { r.Header.Set("Content-MD5", "invalid") }},
		{name: "duplicate authorization", code: "InvalidRequest", mutate: func(r *http.Request) { r.Header.Add(Authorization, r.Header.Get(Authorization)) }},
		{name: "duplicate date", code: "InvalidRequest", mutate: func(r *http.Request) { r.Header.Add("X-Amz-Date", r.Header.Get("X-Amz-Date")) }},
		{name: "malformed date", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Date", "20261107") }},
		{name: "wrong scope date", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) {
			r.Header.Set(Authorization, strings.Replace(r.Header.Get(Authorization), time.Now().UTC().Format("20060102"), "20130524", 1))
		}},
		{name: "wrong service", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) {
			r.Header.Set(Authorization, strings.Replace(r.Header.Get(Authorization), "/s3/", "/sts/", 1))
		}},
		{name: "unsorted signed headers", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) {
			r.Header.Set(Authorization, strings.Replace(r.Header.Get(Authorization), "host;x-amz-date", "x-amz-date;host", 1))
		}},
		{name: "missing signed host", code: "AccessDenied", mutate: func(r *http.Request) {
			r.Header.Set(Authorization, strings.Replace(r.Header.Get(Authorization), "SignedHeaders=host;", "SignedHeaders=", 1))
		}},
		{name: "duplicate signed header", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) {
			r.Header.Set(Authorization, strings.Replace(r.Header.Get(Authorization), "SignedHeaders=host;", "SignedHeaders=host;host;", 1))
		}},
		{name: "malformed raw query", code: "InvalidRequest", mutate: func(r *http.Request) { r.URL.RawQuery = "bad=%ZZ" }},
		{name: "static credential session token", code: "InvalidToken", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "unknown-session") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := newV4TestRequest(t, "PUT", "https://archive.example/new-bucket", "")
			request.Header.Set(TarFilesPerHourHeader, "4")
			request = signer.SignV4(*request, "writer", "secret", "", "us-east-1")
			tc.mutate(request)
			_, _, err := verifyV4(request, time.Now())
			assertV4Failure(t, err, tc.code)
		})
	}
}

func TestVerifyV4PresignRejections(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	cases := []struct {
		name, code string
		mutate     func(*http.Request)
		nowOffset  time.Duration
	}{
		{name: "duplicate auth field", code: "InvalidRequest", mutate: func(r *http.Request) { r.URL.RawQuery += "&X-Amz-Expires=60" }},
		{name: "mixed auth mechanisms", code: "InvalidRequest", mutate: func(r *http.Request) { r.Header.Set(Authorization, "AWS writer:signature") }},
		{name: "expired", code: "AccessDenied", nowOffset: 61 * time.Second},
		{name: "future timestamp", code: "RequestTimeTooSkewed", nowOffset: -16 * time.Minute},
		{name: "zero expiration", code: "AuthorizationQueryParametersError", mutate: func(r *http.Request) { changeV4Query(r, "X-Amz-Expires", "0") }},
		{name: "excessive expiration", code: "AuthorizationQueryParametersError", mutate: func(r *http.Request) { changeV4Query(r, "X-Amz-Expires", "604801") }},
		{name: "noninteger expiration", code: "AuthorizationQueryParametersError", mutate: func(r *http.Request) { changeV4Query(r, "X-Amz-Expires", "1.5") }},
		{name: "missing signature", code: "AuthorizationHeaderMalformed", mutate: func(r *http.Request) {
			query := r.URL.Query()
			query.Del("X-Amz-Signature")
			r.URL.RawQuery = query.Encode()
		}},
		{name: "tampered ordinary parameter", code: "SignatureDoesNotMatch", mutate: func(r *http.Request) { r.URL.RawQuery += "&parse=avro" }},
		{name: "session token", code: "InvalidToken", mutate: func(r *http.Request) { changeV4Query(r, "X-Amz-Security-Token", "session") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := newV4TestRequest(t, "GET", "https://archive.example/data/key", "")
			request = signer.PreSignV4(*request, "writer", "secret", "", "us-east-1", 60)
			if tc.mutate != nil {
				tc.mutate(request)
			}
			_, _, err := verifyV4(request, time.Now().Add(tc.nowOffset))
			assertV4Failure(t, err, tc.code)
		})
	}
}

func TestVerifyV4ClockSkew(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	request := newV4TestRequest(t, "GET", "https://archive.example/data/key", "")
	request = signer.SignV4(*request, "writer", "secret", "", "us-east-1")
	stamp, err := time.Parse(v4TimeFormat, request.Header.Get("X-Amz-Date"))
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []time.Duration{-16 * time.Minute, 16 * time.Minute} {
		_, _, err := verifyV4(request, stamp.Add(offset))
		assertV4Failure(t, err, "RequestTimeTooSkewed")
	}
}

func TestCanonicalV4URIAndQuery(t *testing.T) {
	parsed, err := url.Parse("https://archive.example/bucket/a//../snow%E2%98%83%20%2B%25")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := canonicalV4URI(parsed), "/bucket/a//../snow%E2%98%83%20%2B%25"; got != want {
		t.Fatalf("canonical URI = %q, want %q", got, want)
	}
	query := url.Values{"a": {"z", "+", " "}, "a-": {""}, "é": {"/"}, "z": {"~"}, "X-Amz-Signature": {"signature"}}
	want := "%C3%A9=%2F&a=%20&a=%2B&a=z&a-=&z=~"
	if got := canonicalV4Query(query, true); got != want {
		t.Fatalf("canonical query = %q, want %q", got, want)
	}
	if got := canonicalV4Query(query, false); !strings.Contains(got, "X-Amz-Signature=signature") {
		t.Fatalf("header authentication dropped ordinary signature query: %q", got)
	}
}

func TestS3SecurityV4DispatchAndBody(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	payload := "verified request body"
	request := newV4TestRequest(t, "PUT", "https://archive.example/data/key", payload)
	hash := sha256.Sum256([]byte(payload))
	request.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(hash[:]))
	request = signer.SignV4(*request, "writer", "secret", "", "us-east-1")
	called := false
	handler := S3Security(func(w http.ResponseWriter, r *http.Request, user S3User) {
		called = true
		info, ok := V4Info(r)
		if !ok || info.PayloadHash != hex.EncodeToString(hash[:]) || !user.Write {
			t.Errorf("verified context missing: %+v %+v", info, user)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != payload {
			t.Errorf("body after authentication = %q, %v", body, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("V4 dispatch failed: %d %s", response.Code, response.Body.String())
	}

	request = newV4TestRequest(t, "GET", "https://archive.example/", "")
	request = SignV2(*request, "writer", "secret", false)
	request.Header.Add(Authorization, "AWS4-HMAC-SHA256 invalid")
	response = httptest.NewRecorder()
	S3Security(func(w http.ResponseWriter, r *http.Request, user S3User) {
		t.Error("ambiguous authorization reached handler")
	}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate V2/V4 authorization returned %d", response.Code)
	}
	assertErrorCode(t, response, "InvalidRequest")
}

func TestIsS3RequestPartialQuery(t *testing.T) {
	for name := range v4AuthQueryNames {
		request := httptest.NewRequest("GET", "/?"+name+"=incomplete", nil)
		if !IsS3Request(request) {
			t.Errorf("partial auth field %s would fall through to browser page", name)
		}
	}
	request := httptest.NewRequest("GET", "/?bucket=data", nil)
	if IsS3Request(request) {
		t.Error("ordinary browser query was classified as S3 authentication")
	}
}

func registerV4TestUser(t *testing.T, access, secret string) {
	t.Helper()
	ResetS3Users()
	AddS3User(access, secret, true, true)
	t.Cleanup(ResetS3Users)
}

func newV4TestRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func assertV4Failure(t *testing.T, err error, code string) {
	t.Helper()
	var failure *V4Error
	if !errors.As(err, &failure) {
		t.Fatalf("expected %s error, got %v", code, err)
	}
	if failure.Code != code {
		t.Fatalf("error code = %s, want %s: %s", failure.Code, code, failure.Message)
	}
}

func changeV4Query(r *http.Request, name, value string) {
	query := r.URL.Query()
	query.Set(name, value)
	r.URL.RawQuery = query.Encode()
}

func TestS3SecurityV4RejectsBeforeReadingBody(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	AddS3User("reader", "secret", false, true)
	cases := []struct {
		name, method, access string
		status               int
	}{
		{name: "reader cannot upload", method: "PUT", access: "reader", status: http.StatusForbidden},
		{name: "unsupported method", method: "DELETE", access: "writer", status: http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedV4Body{}
			request := newV4TestRequest(t, tc.method, "https://archive.example/data/key", "")
			request.Body = body
			request.ContentLength = -1
			request = signer.SignV4(*request, tc.access, "secret", "", "us-east-1")
			response := httptest.NewRecorder()
			S3Security(func(w http.ResponseWriter, r *http.Request, user S3User) {
				t.Error("rejected request reached handler")
			}).ServeHTTP(response, request)
			if response.Code != tc.status || body.wasRead {
				t.Fatalf("status=%d, want %d; body read=%v", response.Code, tc.status, body.wasRead)
			}
		})
	}
}

func TestVerifyV4QueryPayloadHash(t *testing.T) {
	registerV4TestUser(t, "writer", "secret")
	request := newV4TestRequest(t, "GET", "https://archive.example/data/key?X-Amz-Content-Sha256=UNSIGNED-PAYLOAD", "")
	request = signer.PreSignV4(*request, "writer", "secret", "", "us-east-1", 60)
	_, info, err := verifyV4(request, time.Now())
	if err != nil || info.PayloadHash != unsignedPayload {
		t.Fatalf("query payload hash rejected: %+v, %v", info, err)
	}
	request.Header.Set("X-Amz-Content-Sha256", v4EmptyHash)
	_, _, err = verifyV4(request, time.Now())
	assertV4Failure(t, err, "InvalidRequest")
	request.Header.Del("X-Amz-Content-Sha256")
	request.URL.RawQuery += "&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD"
	_, _, err = verifyV4(request, time.Now())
	assertV4Failure(t, err, "InvalidRequest")
}

type trackedV4Body struct{ wasRead bool }

func (b *trackedV4Body) Read(data []byte) (int, error) {
	b.wasRead = true
	return 0, io.EOF
}

func (*trackedV4Body) Close() error { return nil }
