package shared

import (
	"archive/tar"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"glacier/archive"
	"mime"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// PAXUserMetadataPrefix stores normalized S3 user metadata suffixes directly.
	PAXUserMetadataPrefix = "S3Glacier.meta."
	// PAXHTTPMetadataPrefix stores supported object representation headers.
	PAXHTTPMetadataPrefix = "S3Glacier.http."
	// PAXETagKey stores the server-computed, unquoted object MD5 hexadecimal ETag.
	PAXETagKey = archive.ETagKey

	objectMetadataLimit = 2 * 1024
	userMetadataPrefix  = "x-amz-meta-"
)

// ErrMetadataTooLarge means normalized user or representation metadata exceeded
// its separate 2 KiB budget. Such errors also match archive.ErrInvalidEntry.
var ErrMetadataTooLarge = errors.New("object metadata exceeds its size limit")

// ObjectMetadata contains object properties, independently of transport headers
// and internal TAR compression. User keys omit x-amz-meta-; Headers contains only
// supported representation headers. ETag is optional, bare lowercase MD5 hex.
// UploadToBucketWithMetadata validates and copies these maps before writing.
type ObjectMetadata struct {
	User    map[string]string
	Headers map[string]string
	ETag    string
}

// ParseObjectMetadata extracts persistent object metadata from request headers.
// Keys are normalized to lowercase. Repeated user metadata and list-valued
// representation headers are joined with commas in value order; repeated
// singleton fields are rejected. User values support RFC 2047 encoded words.
//
// User suffix keys plus decoded UTF-8 values have a combined 2 KiB limit, and
// representation names plus values have a separate 2 KiB limit. All unrelated
// request headers, including authentication and client-supplied ETags, are ignored.
func ParseObjectMetadata(headers http.Header) (ObjectMetadata, error) {
	return parseObjectMetadata(headers, true)
}

func parseObjectMetadata(headers http.Header, decodeUser bool) (ObjectMetadata, error) {
	metadata := ObjectMetadata{User: make(map[string]string), Headers: make(map[string]string)}
	// net/http combines case variants during parsing. Sorting also gives callers
	// with manually assembled noncanonical Header maps a deterministic result.
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)
	userBytes, headerBytes := 0, 0
	for _, name := range names {
		lower := strings.ToLower(name)
		if key, user := strings.CutPrefix(lower, userMetadataPrefix); user {
			if !validMetadataName(name) || !validMetadataName(key) {
				return ObjectMetadata{}, invalidMetadata("invalid user metadata name")
			}
			for _, value := range headers[name] {
				if !validMetadataValue(value) {
					return ObjectMetadata{}, invalidMetadata("invalid user metadata value")
				}
				decoded := value
				if decodeUser {
					var err error
					decoded, err = new(mime.WordDecoder).DecodeHeader(strings.Trim(value, " "))
					if err != nil {
						return ObjectMetadata{}, invalidMetadata("invalid user metadata encoding")
					}
				}
				if !validMetadataValue(decoded) {
					return ObjectMetadata{}, invalidMetadata("invalid user metadata value")
				}
				previous, exists := metadata.User[key]
				cost := len(decoded)
				if exists {
					cost++ // The joining comma is part of the stored value.
				} else {
					cost += len(key)
				}
				if cost > objectMetadataLimit-userBytes {
					return ObjectMetadata{}, metadataTooLarge()
				}
				userBytes += cost
				if exists {
					decoded = previous + "," + decoded
				}
				metadata.User[key] = decoded
			}
			continue
		}
		if !objectRepresentationHeader(lower) {
			continue
		}
		if !validMetadataName(name) {
			return ObjectMetadata{}, invalidMetadata("invalid object representation header name")
		}
		for _, value := range headers[name] {
			if !validMetadataValue(value) {
				return ObjectMetadata{}, invalidMetadata("invalid object representation header")
			}
			value = strings.Trim(value, " ")
			previous, exists := metadata.Headers[lower]
			if exists && !listRepresentationHeader(lower) {
				return ObjectMetadata{}, invalidMetadata("repeated singleton object header")
			}
			if lower == "content-encoding" {
				for encoding := range strings.SplitSeq(value, ",") {
					encoding = strings.TrimSpace(encoding)
					if !validMetadataName(encoding) || strings.EqualFold(encoding, "aws-chunked") {
						return ObjectMetadata{}, invalidMetadata("invalid stored content encoding")
					}
				}
			}
			cost := len(value)
			if exists {
				cost++
			} else {
				cost += len(lower)
			}
			if cost > objectMetadataLimit-headerBytes {
				return ObjectMetadata{}, metadataTooLarge()
			}
			headerBytes += cost
			if exists {
				value = previous + "," + value
			}
			metadata.Headers[lower] = value
		}
	}
	return metadata, nil
}

func objectRepresentationHeader(name string) bool {
	switch name {
	case "content-type", "content-disposition", "content-encoding", "content-language", "cache-control", "expires":
		return true
	default:
		return false
	}
}

func listRepresentationHeader(name string) bool {
	return name == "content-encoding" || name == "content-language" || name == "cache-control"
}

func validMetadataName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func validMetadataValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func invalidMetadata(message string) error {
	return fmt.Errorf("%w: %s", archive.ErrInvalidEntry, message)
}

func metadataTooLarge() error {
	return fmt.Errorf("%w: %w", archive.ErrInvalidEntry, ErrMetadataTooLarge)
}

func normalizeObjectMetadata(metadata ObjectMetadata) (ObjectMetadata, error) {
	headers := make(http.Header, len(metadata.User)+len(metadata.Headers))
	for key, value := range metadata.User {
		headers[userMetadataPrefix+key] = []string{value}
	}
	for key, value := range metadata.Headers {
		if !objectRepresentationHeader(strings.ToLower(key)) {
			return ObjectMetadata{}, invalidMetadata("unsupported object representation header")
		}
		headers[key] = []string{value}
	}
	// ObjectMetadata already contains decoded values. Decoding again would alter
	// legitimate text that happens to contain an RFC 2047 encoded-word pattern.
	normalized, err := parseObjectMetadata(headers, false)
	if err != nil {
		return ObjectMetadata{}, err
	}
	if metadata.ETag != "" {
		if !validObjectETag(metadata.ETag) {
			return ObjectMetadata{}, invalidMetadata("invalid object ETag")
		}
		normalized.ETag = metadata.ETag
	}
	return normalized, nil
}

func validObjectETag(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (metadata ObjectMetadata) paxRecords() map[string]string {
	records := make(map[string]string, len(metadata.User)+len(metadata.Headers)+1)
	for key, value := range metadata.User {
		records[PAXUserMetadataPrefix+key] = value
	}
	for key, value := range metadata.Headers {
		records[PAXHTTPMetadataPrefix+key] = value
	}
	if metadata.ETag != "" {
		records[PAXETagKey] = metadata.ETag
	}
	return records
}

// ObjectMetadataFromTar reads supported direct PAX fields. Legacy entries with
// no such fields return empty metadata. Invalid reserved metadata returns
// archive.ErrCorrupt, preventing malformed headers from reaching HTTP responses.
func ObjectMetadataFromTar(header *tar.Header) (ObjectMetadata, error) {
	if header == nil {
		return ObjectMetadata{}, fmt.Errorf("%w: missing object header", archive.ErrCorrupt)
	}
	metadata := ObjectMetadata{User: make(map[string]string), Headers: make(map[string]string)}
	for key, value := range header.PAXRecords {
		if name, ok := strings.CutPrefix(key, PAXUserMetadataPrefix); ok {
			metadata.User[name] = value
		} else if name, ok := strings.CutPrefix(key, PAXHTTPMetadataPrefix); ok {
			metadata.Headers[name] = value
		}
	}
	if value, exists := header.PAXRecords[PAXETagKey]; exists {
		if !validObjectETag(value) {
			return ObjectMetadata{}, fmt.Errorf("%w: invalid stored ETag", archive.ErrCorrupt)
		}
		metadata.ETag = value
	}
	metadata, err := normalizeObjectMetadata(metadata)
	if err != nil {
		return ObjectMetadata{}, fmt.Errorf("%w: invalid stored object metadata: %v", archive.ErrCorrupt, err)
	}
	return metadata, nil
}

func applyObjectMetadata(headers http.Header, metadata ObjectMetadata, contentType string) {
	if contentType != "" {
		headers.Set("Content-Type", contentType)
	}
	for key, value := range metadata.Headers {
		if key != "content-type" || value != "" {
			headers.Set(key, value)
		}
	}
	for key, value := range metadata.User {
		headers.Set(userMetadataPrefix+key, encodeUserMetadata(value))
	}
	if metadata.ETag != "" {
		headers.Set("ETag", `"`+metadata.ETag+`"`)
	}
}

func encodeUserMetadata(value string) string {
	encoded := mime.BEncoding.Encode("UTF-8", value)
	if encoded != value {
		return encoded
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(value)
	if err == nil && decoded == value && strings.Trim(value, " ") == value {
		return value
	}
	// mime.WordEncoder leaves ASCII unchanged, including literal encoded-word
	// text. Wrap that text so a client's single MIME decode preserves it. This
	// branch is ASCII-only; 45-byte chunks keep every encoded word below 75 bytes.
	var output strings.Builder
	for len(value) > 0 {
		if output.Len() > 0 {
			output.WriteByte(' ')
		}
		count := min(len(value), 45)
		output.WriteString("=?UTF-8?B?")
		output.WriteString(base64.StdEncoding.EncodeToString([]byte(value[:count])))
		output.WriteString("?=")
		value = value[count:]
	}
	return output.String()
}

// ClearObjectMetadataHeaders removes object-specific headers before sending an
// error or a transformed representation. It handles noncanonical Header maps too.
func ClearObjectMetadataHeaders(headers http.Header) {
	for name := range headers {
		lower := strings.ToLower(name)
		if objectRepresentationHeader(lower) || strings.HasPrefix(lower, userMetadataPrefix) || lower == "etag" || lower == "content-length" || lower == "last-modified" {
			delete(headers, name)
		}
	}
}
