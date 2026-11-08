package s3

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"glacier/bucket"
	"io"
	"strings"
	"time"
)

const listTokenDomain = "S3Glacier ListObjectsV2 continuation token v1\x00"

type listCursor struct {
	Version int    `json:"v"`
	Scope   string `json:"scope"`
	After   string `json:"after"`
}

// The scope binds the cursor to a bucket incarnation and the logical filter.
// Page size, response encoding and owner display may change between pages.
func listTokenScope(b bucket.Bucket, q listQuery) string {
	data, _ := json.Marshal(struct {
		Bucket, Created, Path, Prefix, Delimiter string
		Extended                                 bool
	}{b.Name, b.CreatedAt.UTC().Format(time.RFC3339Nano), b.Path, q.prefix, q.delimiter, q.extended})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func listTokenMAC(data []byte, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(listTokenDomain))
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func encodeListToken(after string, b bucket.Bucket, q listQuery, secret string) (string, error) {
	data, err := json.Marshal(listCursor{Version: 1, Scope: listTokenScope(b, q), After: after})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(listTokenMAC(data, secret)), nil
}

func decodeListToken(token string, b bucket.Bucket, q listQuery, secret string) (string, error) {
	invalid := errors.New("invalid continuation token")
	if len(token) > 4096 {
		return "", invalid
	}
	body, signature, ok := strings.Cut(token, ".")
	if !ok {
		return "", invalid
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return "", invalid
	}
	mac, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || !hmac.Equal(mac, listTokenMAC(data, secret)) {
		return "", invalid
	}
	var cursor listCursor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil {
		return "", invalid
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", invalid
	}
	if cursor.Version != 1 || cursor.Scope != listTokenScope(b, q) || cursor.After == "" || len(cursor.After) > 36 || !strings.HasPrefix(cursor.After, q.prefix) {
		return "", invalid
	}
	return cursor.After, nil
}
