package s3

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/minio/crc64nvme"
)

const (
	v4StreamingPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	v4StreamingTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	v4UnsignedTrailer  = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	v4EmptyHash        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// verifiedPayload retains the upload buffer used by the existing archive writer.
// ObjectHandler can reuse these bytes without reading a second full copy.
type verifiedPayload struct {
	*bytes.Reader
	data []byte
}

func (*verifiedPayload) Close() error { return nil }

func readS3Body(r *http.Request) ([]byte, error) {
	if body, ok := r.Body.(*verifiedPayload); ok {
		return body.data, nil
	}
	return io.ReadAll(r.Body)
}

// VerifyV4Payload verifies the entire payload before a handler can mutate a
// bucket or archive. Streaming framing is removed before bytes reach storage.
// Like the archive upload handler, this buffers one complete decoded object.
func VerifyV4Payload(r *http.Request, info *V4SigningInfo) error {
	if r.Body == nil {
		r.Body = http.NoBody
	}
	defer r.Body.Close()
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil {
			return payloadError("IncompleteBody", "Unable to read the request body.")
		}
		if len(body) != 0 || info.Streaming || hasContentEncoding(r, "aws-chunked") {
			return payloadError("InvalidRequest", "GET and HEAD requests do not accept a body.")
		}
	}
	var data []byte
	var err error
	switch info.PayloadHash {
	case v4StreamingPayload, v4StreamingTrailer, v4UnsignedTrailer:
		data, err = decodeV4Chunks(r, info)
	default:
		if hasContentEncoding(r, "aws-chunked") || r.Header.Get("X-Amz-Trailer") != "" {
			return payloadError("InvalidRequest", "Chunked payloads require a supported streaming signature mode.")
		}
		data, err = io.ReadAll(r.Body)
		if err != nil {
			return payloadError("IncompleteBody", "Unable to read the request body.")
		}
		if info.PayloadHash != "UNSIGNED-PAYLOAD" {
			expected, decodeErr := hex.DecodeString(info.PayloadHash)
			actual := sha256.Sum256(data)
			if decodeErr != nil || !hmac.Equal(expected, actual[:]) {
				return payloadError("XAmzContentSHA256Mismatch", "The payload does not match x-amz-content-sha256.")
			}
		}
	}
	if err != nil {
		return err
	}
	if err := verifyV4Checksums(r.Header, data); err != nil {
		return err
	}
	// Presigners can move x-amz checksum headers into the signed query string.
	// Those checksums have the same integrity semantics as request headers.
	queryChecksums := make(http.Header)
	for name, values := range r.URL.Query() {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-amz-checksum-") {
			continue
		}
		for _, value := range values {
			queryChecksums.Add(name, value)
		}
		if headers := r.Header.Values(name); len(headers) != 0 && (len(headers) != 1 || len(values) != 1 || headers[0] != values[0]) {
			return payloadError("InvalidRequest", "Header and query checksum values conflict.")
		}
	}
	if err := verifyV4Checksums(queryChecksums, data); err != nil {
		return err
	}
	r.Body = &verifiedPayload{Reader: bytes.NewReader(data), data: data}
	r.ContentLength = int64(len(data))
	return nil
}

func payloadError(code, message string) *V4Error {
	return &V4Error{Status: http.StatusBadRequest, Code: code, Message: message}
}

func hasContentEncoding(r *http.Request, encoding string) bool {
	for _, line := range r.Header.Values("Content-Encoding") {
		for _, value := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(value), encoding) {
				return true
			}
		}
	}
	return false
}

func decodeV4Chunks(r *http.Request, info *V4SigningInfo) ([]byte, error) {
	lengths := r.Header.Values("X-Amz-Decoded-Content-Length")
	if !hasContentEncoding(r, "aws-chunked") || len(lengths) != 1 || lengths[0] == "" || strings.Trim(lengths[0], "0123456789") != "" {
		return nil, payloadError("InvalidRequest", "Streaming uploads require aws-chunked encoding and a decoded content length.")
	}
	length, err := strconv.ParseInt(lengths[0], 10, 64)
	if err != nil {
		return nil, payloadError("InvalidRequest", "The decoded content length is invalid.")
	}
	trailerMode := info.PayloadHash != v4StreamingPayload
	if !trailerMode && r.Header.Get("X-Amz-Trailer") != "" {
		return nil, payloadError("InvalidRequest", "The payload mode does not allow trailers.")
	}
	signed := info.PayloadHash != v4UnsignedTrailer
	reader := bufio.NewReaderSize(r.Body, 4096)
	previous := info.SeedSignature
	var decoded bytes.Buffer
	for {
		line, err := readV4Line(reader, true)
		if err != nil {
			return nil, err
		}
		sizeText, signature, found := strings.Cut(line, ";chunk-signature=")
		if found != signed || sizeText == "" || strings.Trim(sizeText, "0123456789abcdefABCDEF") != "" {
			return nil, payloadError("InvalidRequest", "The streaming chunk header is invalid.")
		}
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil || size > length-int64(decoded.Len()) {
			return nil, payloadError("InvalidRequest", "The streaming chunk exceeds the decoded content length.")
		}
		chunkHash := sha256.New()
		if _, err := io.CopyN(io.MultiWriter(&decoded, chunkHash), reader, size); err != nil {
			return nil, payloadError("IncompleteBody", "The streaming chunk is incomplete.")
		}
		if signed {
			stringToSign := strings.Join([]string{
				"AWS4-HMAC-SHA256-PAYLOAD", info.AmzDate, info.Scope, previous,
				v4EmptyHash, hex.EncodeToString(chunkHash.Sum(nil)),
			}, "\n")
			if !validV4PayloadSignature(info.SigningKey, stringToSign, signature) {
				return nil, &V4Error{Status: http.StatusForbidden, Code: "SignatureDoesNotMatch", Message: "A streaming chunk signature does not match."}
			}
			previous = signature
		}
		if size == 0 {
			break
		}
		if line, err := readV4Line(reader, true); err != nil || line != "" {
			return nil, payloadError("IncompleteBody", "The streaming chunk terminator is invalid.")
		}
	}
	if int64(decoded.Len()) != length {
		return nil, payloadError("IncompleteBody", "The streaming payload does not match the decoded content length.")
	}
	if trailerMode {
		if err := verifyV4Trailers(reader, r, info, previous, decoded.Bytes()); err != nil {
			return nil, err
		}
	} else if line, err := readV4Line(reader, true); err != nil || line != "" {
		return nil, payloadError("IncompleteBody", "The final streaming chunk terminator is invalid.")
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		return nil, payloadError("InvalidRequest", "Unexpected data follows the streaming payload.")
	}
	// aws-chunked describes wire framing, not the stored object's encoding.
	var encodings []string
	for _, line := range r.Header.Values("Content-Encoding") {
		for _, value := range strings.Split(line, ",") {
			if value = strings.TrimSpace(value); !strings.EqualFold(value, "aws-chunked") && value != "" {
				encodings = append(encodings, value)
			}
		}
	}
	r.Header.Del("Content-Encoding")
	if len(encodings) != 0 {
		r.Header.Set("Content-Encoding", strings.Join(encodings, ","))
	}
	return decoded.Bytes(), nil
}

// Chunk headers require CRLF. Trailer implementations also use LF lines; AWS
// canonicalizes those lines with LF when calculating the trailer signature.
func readV4Line(reader *bufio.Reader, requireCRLF bool) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return "", payloadError("IncompleteBody", "The streaming framing is incomplete or too long.")
	}
	line = line[:len(line)-1]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	} else if requireCRLF {
		return "", payloadError("InvalidRequest", "Streaming chunks require CRLF delimiters.")
	}
	return string(line), nil
}

func validV4PayloadSignature(key []byte, value, signature string) bool {
	supplied, err := hex.DecodeString(signature)
	if err != nil || len(supplied) != sha256.Size || signature != strings.ToLower(signature) {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, value)
	return hmac.Equal(supplied, mac.Sum(nil))
}

func verifyV4Trailers(reader *bufio.Reader, r *http.Request, info *V4SigningInfo, previous string, data []byte) error {
	names := strings.Split(strings.Join(r.Header.Values("X-Amz-Trailer"), ","), ",")
	expected := make(map[string]bool, len(names))
	for i, name := range names {
		name = strings.TrimSpace(name)
		if expected[name] || newV4Checksum(name) == nil {
			return payloadError("InvalidRequest", "The streaming checksum trailer is unsupported or duplicated.")
		}
		names[i] = name
		expected[name] = true
	}
	slices.Sort(names)
	trailers := make(http.Header)
	for range names {
		line, err := readV4Line(reader, false)
		if err != nil {
			return err
		}
		name, value, ok := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		if !ok || !expected[name] || value == "" {
			return payloadError("InvalidRequest", "The streaming trailers do not match x-amz-trailer.")
		}
		delete(expected, name)
		trailers.Set(name, value)
	}
	// MinIO emits an additional CRLF after its LF-terminated checksum lines.
	line, err := readV4Line(reader, true)
	if err != nil {
		return err
	}
	if info.PayloadHash == v4StreamingTrailer {
		if line == "" {
			line, err = readV4Line(reader, true)
			if err != nil {
				return err
			}
		}
		name, signature, ok := strings.Cut(line, ":")
		if !ok || name != "x-amz-trailer-signature" {
			return payloadError("InvalidRequest", "The streaming trailer signature is missing.")
		}
		var canonical strings.Builder
		for _, name := range names {
			canonical.WriteString(name + ":" + trailers.Get(name) + "\n")
		}
		checksum := sha256.Sum256([]byte(canonical.String()))
		stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256-TRAILER", info.AmzDate, info.Scope, previous, hex.EncodeToString(checksum[:])}, "\n")
		if !validV4PayloadSignature(info.SigningKey, stringToSign, signature) {
			return &V4Error{Status: http.StatusForbidden, Code: "SignatureDoesNotMatch", Message: "The streaming trailer signature does not match."}
		}
		line, err = readV4Line(reader, true)
		if err != nil {
			return err
		}
	}
	if line != "" {
		return payloadError("InvalidRequest", "The streaming trailer terminator is invalid.")
	}
	// Some SDKs add one further empty line after LF-terminated trailers.
	if next, _ := reader.Peek(2); bytes.Equal(next, []byte("\r\n")) {
		_, _ = reader.Discard(2)
	}
	return verifyV4Checksums(trailers, data)
}

func newV4Checksum(name string) hash.Hash {
	switch name {
	case "x-amz-checksum-crc32":
		return crc32.NewIEEE()
	case "x-amz-checksum-crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "x-amz-checksum-crc64nvme":
		return crc64nvme.New()
	case "x-amz-checksum-sha1":
		return sha1.New()
	case "x-amz-checksum-sha256":
		return sha256.New()
	default:
		return nil
	}
}

func verifyV4Checksums(headers http.Header, data []byte) error {
	for name, values := range headers {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-amz-checksum-") || lower == "x-amz-checksum-algorithm" || lower == "x-amz-checksum-type" || lower == "x-amz-checksum-mode" {
			continue
		}
		hasher := newV4Checksum(lower)
		if hasher == nil || len(values) != 1 {
			return payloadError("InvalidRequest", "The payload checksum is unsupported or duplicated.")
		}
		expected, err := base64.StdEncoding.DecodeString(values[0])
		if err != nil {
			return payloadError("InvalidDigest", "The payload checksum is invalid.")
		}
		_, _ = hasher.Write(data)
		if !hmac.Equal(expected, hasher.Sum(nil)) {
			return payloadError("BadDigest", "The payload checksum does not match the object body.")
		}
	}
	return nil
}
