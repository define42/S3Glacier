package s3

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/crc64nvme"
	"github.com/minio/minio-go/v7/pkg/signer"
)

const (
	payloadTestAccessKey = "AKIAIOSFODNN7EXAMPLE"
	payloadTestSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	payloadTestRegion    = "us-east-1"
)

func TestVerifyV4PayloadSingleChunk(t *testing.T) {
	t.Parallel()
	data := []byte("single chunk object")
	sum := sha256.Sum256(data)
	tests := []struct {
		name     string
		body     []byte
		hash     string
		encoding string
		wantCode string
	}{
		{name: "hashed payload", body: data, hash: hex.EncodeToString(sum[:])},
		{name: "unsigned payload", body: data, hash: "UNSIGNED-PAYLOAD"},
		{name: "empty payload", hash: v4EmptyHash},
		{name: "tampered payload", body: []byte("different bytes"), hash: hex.EncodeToString(sum[:]), wantCode: "XAmzContentSHA256Mismatch"},
		{name: "malformed hash", body: data, hash: "not-a-hash", wantCode: "XAmzContentSHA256Mismatch"},
		{name: "unexpected streaming encoding", body: data, hash: "UNSIGNED-PAYLOAD", encoding: "aws-chunked", wantCode: "InvalidRequest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/data/object", bytes.NewReader(tt.body))
			request.Header.Set("Content-Encoding", tt.encoding)
			err := VerifyV4Payload(request, &V4SigningInfo{PayloadHash: tt.hash})
			assertPayloadError(t, err, tt.wantCode)
			if err == nil {
				assertDecodedPayload(t, request, tt.body)
			}
		})
	}
}

func TestVerifyV4PayloadReadRequestsBoundBodyRead(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" empty payload", func(t *testing.T) {
			request := httptest.NewRequest(method, "/data/object", nil)
			if err := VerifyV4Payload(request, &V4SigningInfo{PayloadHash: v4EmptyHash}); err != nil {
				t.Fatal(err)
			}
			assertDecodedPayload(t, request, nil)
		})
		t.Run(method+" oversized payload", func(t *testing.T) {
			probe := &oversizedPayloadReader{}
			request := httptest.NewRequest(method, "/data/object", nil)
			request.Body = io.NopCloser(probe)
			request.ContentLength = 1 << 40
			assertPayloadError(t, VerifyV4Payload(request, &V4SigningInfo{PayloadHash: "UNSIGNED-PAYLOAD"}), "InvalidRequest")
			if probe.bytesRead != 1 {
				t.Fatalf("read %d payload bytes, want only one byte before rejecting the request", probe.bytesRead)
			}
		})
	}
}

func TestVerifyV4PayloadAWSStreamingVector(t *testing.T) {
	t.Parallel()
	// AWS's published 64 KiB + 1 KiB example pins the chunk signatures rather
	// than deriving expected signatures with this server's implementation.
	// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html
	data := bytes.Repeat([]byte("a"), 66560)
	var wire bytes.Buffer
	wire.WriteString("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n")
	wire.Write(data[:65536])
	wire.WriteString("\r\n400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n")
	wire.Write(data[65536:])
	wire.WriteString("\r\n0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n")
	request := httptest.NewRequest(http.MethodPut, "/examplebucket/chunkObject.txt", &wire)
	request.Header.Set("Content-Encoding", "aws-chunked")
	request.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	info := &V4SigningInfo{
		PayloadHash: v4StreamingPayload, AmzDate: "20130524T000000Z",
		Scope:         "20130524/us-east-1/s3/aws4_request",
		SeedSignature: "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9",
		SigningKey:    payloadSigningKey("20130524"),
	}
	if err := VerifyV4Payload(request, info); err != nil {
		t.Fatal(err)
	}
	assertDecodedPayload(t, request, data)
}

func TestVerifyV4PayloadMinioStreaming(t *testing.T) {
	t.Parallel()
	data := bytes.Repeat([]byte("sdk object bytes"), 5000)
	tests := []struct {
		name      string
		signed    bool
		checksums []string
	}{
		{name: "signed chunks", signed: true},
		{name: "signed sha256 trailer", signed: true, checksums: []string{"sha256"}},
		{name: "signed crc32c trailer", signed: true, checksums: []string{"crc32c"}},
		{name: "signed crc32 trailer", signed: true, checksums: []string{"crc32"}},
		{name: "signed crc64nvme trailer", signed: true, checksums: []string{"crc64nvme"}},
		{name: "signed sha1 trailer", signed: true, checksums: []string{"sha1"}},
		{name: "unsigned sha256 trailer", checksums: []string{"sha256"}},
		{name: "unsigned crc32c trailer", checksums: []string{"crc32c"}},
		{name: "unsigned crc32 trailer", checksums: []string{"crc32"}},
		{name: "unsigned crc64nvme trailer", checksums: []string{"crc64nvme"}},
		{name: "unsigned sha1 trailer", checksums: []string{"sha1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trailers := make(http.Header)
			for _, name := range tt.checksums {
				trailers.Set("X-Amz-Checksum-"+name, payloadChecksum(name, data))
			}
			request, info := sdkStreamingPayload(t, data, tt.signed, trailers)
			if err := VerifyV4Payload(request, info); err != nil {
				t.Fatal(err)
			}
			assertDecodedPayload(t, request, data)
			if got := request.Header.Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("content encoding = %q, want retained gzip encoding without aws-chunked", got)
			}
		})
	}
}

func TestVerifyV4PayloadRejectsMalformedChunks(t *testing.T) {
	t.Parallel()
	data := bytes.Repeat([]byte("a"), 70000)
	request, info := sdkStreamingPayload(t, data, true, nil)
	wire, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = request.Body.Close()
	tests := []struct {
		name     string
		mutate   func(*http.Request, []byte) []byte
		wantCode string
	}{
		{name: "tampered chunk bytes", wantCode: "SignatureDoesNotMatch", mutate: func(_ *http.Request, body []byte) []byte {
			body[bytes.Index(body, []byte("\r\n"))+2] = 'b'
			return body
		}},
		{name: "tampered final signature", wantCode: "SignatureDoesNotMatch", mutate: func(_ *http.Request, body []byte) []byte {
			index := bytes.LastIndex(body, []byte(";chunk-signature=")) + len(";chunk-signature=")
			body[index] = differentHex(body[index])
			return body
		}},
		{name: "truncated chunk data", wantCode: "IncompleteBody", mutate: func(_ *http.Request, body []byte) []byte {
			return body[:bytes.Index(body, []byte("\r\n"))+12]
		}},
		{name: "missing final chunk", wantCode: "IncompleteBody", mutate: func(_ *http.Request, body []byte) []byte {
			return body[:bytes.LastIndex(body, []byte("0;chunk-signature="))]
		}},
		{name: "missing final terminator", wantCode: "IncompleteBody", mutate: func(_ *http.Request, body []byte) []byte {
			return body[:len(body)-2]
		}},
		{name: "data after final chunk", wantCode: "InvalidRequest", mutate: func(_ *http.Request, body []byte) []byte {
			return append(body, 'x')
		}},
		{name: "invalid chunk size", wantCode: "InvalidRequest", mutate: func(_ *http.Request, body []byte) []byte {
			body[0] = 'g'
			return body
		}},
		{name: "oversized chunk", wantCode: "InvalidRequest", mutate: func(_ *http.Request, body []byte) []byte {
			return append([]byte("7fffffffffffffff"), body[bytes.IndexByte(body, ';'):]...)
		}},
		{name: "LF chunk delimiter", wantCode: "InvalidRequest", mutate: func(_ *http.Request, body []byte) []byte {
			return bytes.Replace(body, []byte("\r\n"), []byte("\n"), 1)
		}},
		{name: "too small decoded length", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)-1))
			return body
		}},
		{name: "too large decoded length", wantCode: "IncompleteBody", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)+1))
			return body
		}},
		{name: "negative decoded length", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Decoded-Content-Length", "-1")
			return body
		}},
		{name: "overflow decoded length", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Decoded-Content-Length", "9223372036854775808")
			return body
		}},
		{name: "duplicate decoded length", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Add("X-Amz-Decoded-Content-Length", strconv.Itoa(len(data)))
			return body
		}},
		{name: "missing decoded length", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Del("X-Amz-Decoded-Content-Length")
			return body
		}},
		{name: "missing streaming encoding", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Del("Content-Encoding")
			return body
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := request.Clone(t.Context())
			changedWire := tt.mutate(changed, bytes.Clone(wire))
			changed.Body = io.NopCloser(bytes.NewReader(changedWire))
			assertPayloadError(t, VerifyV4Payload(changed, info), tt.wantCode)
		})
	}
}

func TestVerifyV4PayloadRejectsMalformedTrailers(t *testing.T) {
	t.Parallel()
	data := []byte("trailer verified bytes")
	for _, signed := range []bool{true, false} {
		name := "unsigned"
		if signed {
			name = "signed"
		}
		t.Run(name+" wrong checksum", func(t *testing.T) {
			trailer := http.Header{"X-Amz-Checksum-Sha256": []string{payloadChecksum("sha256", []byte("different data"))}}
			request, info := sdkStreamingPayload(t, data, signed, trailer)
			assertPayloadError(t, VerifyV4Payload(request, info), "BadDigest")
		})
	}
	trailer := http.Header{"X-Amz-Checksum-Sha256": []string{payloadChecksum("sha256", data)}}
	request, info := sdkStreamingPayload(t, data, true, trailer)
	wire, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = request.Body.Close()
	tests := []struct {
		name     string
		mutate   func(*http.Request, []byte) []byte
		wantCode string
	}{
		{name: "tampered trailer signature", wantCode: "SignatureDoesNotMatch", mutate: func(_ *http.Request, body []byte) []byte {
			index := bytes.Index(body, []byte("x-amz-trailer-signature:")) + len("x-amz-trailer-signature:")
			body[index] = differentHex(body[index])
			return body
		}},
		{name: "missing trailer signature", wantCode: "IncompleteBody", mutate: func(_ *http.Request, body []byte) []byte {
			return body[:bytes.Index(body, []byte("x-amz-trailer-signature:"))]
		}},
		{name: "unannounced trailer", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32c")
			return body
		}},
		{name: "unsupported trailer", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Set("X-Amz-Trailer", "x-amz-unknown")
			return body
		}},
		{name: "duplicate announced trailer", wantCode: "InvalidRequest", mutate: func(request *http.Request, body []byte) []byte {
			request.Header.Add("X-Amz-Trailer", "x-amz-checksum-sha256")
			return body
		}},
		{name: "extra bytes after trailer", wantCode: "InvalidRequest", mutate: func(_ *http.Request, body []byte) []byte {
			return append(body, 'x')
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := request.Clone(t.Context())
			changed.Body = io.NopCloser(bytes.NewReader(tt.mutate(changed, bytes.Clone(wire))))
			assertPayloadError(t, VerifyV4Payload(changed, info), tt.wantCode)
		})
	}
}

func TestVerifyV4PayloadHeaderChecksums(t *testing.T) {
	t.Parallel()
	data := []byte("checksum protected bytes")
	for _, name := range []string{"crc32", "crc32c", "crc64nvme", "sha1", "sha256"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/data/object", bytes.NewReader(data))
			request.Header.Set("X-Amz-Checksum-"+name, payloadChecksum(name, data))
			if err := VerifyV4Payload(request, &V4SigningInfo{PayloadHash: "UNSIGNED-PAYLOAD"}); err != nil {
				t.Fatal(err)
			}
		})
	}
	tests := []struct {
		name     string
		header   string
		values   []string
		wantCode string
	}{
		{name: "bad checksum", header: "X-Amz-Checksum-Sha256", values: []string{payloadChecksum("sha256", []byte("other"))}, wantCode: "BadDigest"},
		{name: "invalid base64", header: "X-Amz-Checksum-Sha256", values: []string{"not base64!"}, wantCode: "InvalidDigest"},
		{name: "duplicate checksum", header: "X-Amz-Checksum-Sha256", values: []string{"value", "value"}, wantCode: "InvalidRequest"},
		{name: "unsupported checksum", header: "X-Amz-Checksum-Unknown", values: []string{"value"}, wantCode: "InvalidRequest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/data/object", bytes.NewReader(data))
			request.Header[tt.header] = tt.values
			assertPayloadError(t, VerifyV4Payload(request, &V4SigningInfo{PayloadHash: "UNSIGNED-PAYLOAD"}), tt.wantCode)
		})
	}
}

type payloadHashWrapper struct{ hash.Hash }

func (*payloadHashWrapper) Close() {}

// An effectively unbounded body that fails the test quickly if the verifier
// requests more than its one-byte probe instead of limiting the source read.
type oversizedPayloadReader struct{ bytesRead int }

func (r *oversizedPayloadReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		return 0, errors.New("request body read was not bounded to one byte")
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	r.bytesRead++
	return 1, nil
}

// sdkStreamingPayload uses MinIO's independent signer/framer. Header signature
// verification is tested separately; these tests pin decoding and integrity.
func sdkStreamingPayload(t *testing.T, data []byte, signed bool, trailers http.Header) (*http.Request, *V4SigningInfo) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPut, "http://localhost:9000/data/object", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Encoding", "gzip")
	if signed {
		request.Trailer = trailers
		request = signer.StreamingSignV4(request, payloadTestAccessKey, payloadTestSecretKey, "", payloadTestRegion,
			int64(len(data)), time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), &payloadHashWrapper{Hash: sha256.New()})
	} else {
		request.Header.Set("X-Amz-Content-Sha256", v4UnsignedTrailer)
		request = signer.SignV4Trailer(*request, payloadTestAccessKey, payloadTestSecretKey, "", payloadTestRegion, trailers)
	}
	_, signature, found := strings.Cut(request.Header.Get("Authorization"), "Signature=")
	if !found {
		t.Fatal("SDK request has no seed signature")
	}
	date := request.Header.Get("X-Amz-Date")
	info := &V4SigningInfo{
		PayloadHash: request.Header.Get("X-Amz-Content-Sha256"), AmzDate: date,
		Scope:         date[:8] + "/" + payloadTestRegion + "/s3/aws4_request",
		SeedSignature: signature, SigningKey: payloadSigningKey(date[:8]),
	}
	return request, info
}

func payloadSigningKey(date string) []byte {
	key := []byte("AWS4" + payloadTestSecretKey)
	for _, part := range []string{date, payloadTestRegion, "s3", "aws4_request"} {
		mac := hmac.New(sha256.New, key)
		_, _ = io.WriteString(mac, part)
		key = mac.Sum(nil)
	}
	return key
}

func payloadChecksum(name string, data []byte) string {
	var hasher hash.Hash
	switch name {
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "crc32":
		hasher = crc32.NewIEEE()
	case "crc32c":
		hasher = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "crc64nvme":
		hasher = crc64nvme.New()
	default:
		panic("unsupported test checksum")
	}
	_, _ = hasher.Write(data)
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

func assertDecodedPayload(t *testing.T, request *http.Request, want []byte) {
	t.Helper()
	decoded, err := readS3Body(request)
	if err != nil || !bytes.Equal(decoded, want) {
		t.Fatalf("decoded payload differs: got %d bytes, want %d, error = %v", len(decoded), len(want), err)
	}
	if request.ContentLength != int64(len(want)) {
		t.Fatalf("decoded ContentLength = %d, want %d", request.ContentLength, len(want))
	}
}

func assertPayloadError(t *testing.T, err error, wantCode string) {
	t.Helper()
	if wantCode == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if v4Err, ok := errors.AsType[*V4Error](err); !ok || v4Err.Code != wantCode {
		t.Fatalf("payload error = %v, want code %s", err, wantCode)
	}
}

func differentHex(value byte) byte {
	if value == '0' {
		return '1'
	}
	return '0'
}
