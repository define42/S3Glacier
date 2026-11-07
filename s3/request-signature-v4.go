package s3

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	v4TimeFormat    = "20060102T150405Z"
	v4ClockSkew     = 15 * time.Minute
	v4MaxExpires    = 7 * 24 * 60 * 60
)

// V4SigningInfo contains verified request information used to authenticate its body.
// SigningKey is scoped to this request's date, region, and S3 service.
type V4SigningInfo struct {
	SigningKey    []byte
	Scope         string
	AmzDate       string
	SeedSignature string
	PayloadHash   string
	Streaming     bool
	Trailer       bool
	Presigned     bool
}

// V4Error is an S3 protocol error raised while authenticating a V4 request.
type V4Error struct {
	Status  int
	Code    string
	Message string
}

func (e *V4Error) Error() string { return e.Message }

type v4InfoContextKey struct{}

// V4Info returns signing information after S3Security has authenticated a V4 request.
func V4Info(r *http.Request) (*V4SigningInfo, bool) {
	info, ok := r.Context().Value(v4InfoContextKey{}).(*V4SigningInfo)
	return info, ok
}

var v4AuthQueryNames = map[string]bool{
	"X-Amz-Algorithm": true, "X-Amz-Credential": true, "X-Amz-Date": true,
	"X-Amz-Expires": true, "X-Amz-SignedHeaders": true, "X-Amz-Signature": true,
	"X-Amz-Security-Token": true, "X-Amz-Content-Sha256": true,
}

// IsS3Request distinguishes signed S3 requests from the browser's root page.
// Partial query credentials also enter authentication, where they fail closed.
func IsS3Request(r *http.Request) bool {
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get(Authorization)), "AWS") {
		return true
	}
	return hasV4Query(r)
}

func hasV4Query(r *http.Request) bool {
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		name, _, _ := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(name)
		if err == nil && v4AuthQueryNames[decoded] {
			return true
		}
	}
	return false
}

func withV4Info(r *http.Request, info *V4SigningInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), v4InfoContextKey{}, info))
}

type v4Credentials struct {
	accessKey     string
	scope         string
	date          string
	region        string
	amzDate       string
	signedHeaders string
	signature     string
	presigned     bool
	expires       int64
}

func verifyV4(r *http.Request, now time.Time) (S3User, *V4SigningInfo, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return S3User{}, nil, v4Error(http.StatusBadRequest, "InvalidRequest", "The query string is malformed.")
	}
	credentials, err := parseV4Credentials(r, query)
	if err != nil {
		return S3User{}, nil, err
	}
	if err := credentials.checkTime(now); err != nil {
		return S3User{}, nil, err
	}

	s3UsersList.mu.RLock()
	user, ok := s3UsersList.m[credentials.accessKey]
	s3UsersList.mu.RUnlock()
	if !ok {
		return S3User{}, nil, v4Error(http.StatusForbidden, "InvalidAccessKeyId", "The access key does not exist.")
	}

	headers, err := canonicalV4Headers(r, credentials.signedHeaders, query)
	if err != nil {
		return S3User{}, nil, err
	}
	payloadHash, err := v4PayloadHash(r, query)
	if err != nil {
		return S3User{}, nil, err
	}
	canonical := strings.Join([]string{
		r.Method, canonicalV4URI(r.URL), canonicalV4Query(query, credentials.presigned),
		headers, credentials.signedHeaders, payloadHash,
	}, "\n")
	hash := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		signV4Algorithm, credentials.amzDate, credentials.scope, hex.EncodeToString(hash[:]),
	}, "\n")
	key := v4SigningKey(user.SecretAccessKey, credentials.date, credentials.region)
	expected := sumHMAC(key, []byte(stringToSign))
	provided, err := hex.DecodeString(credentials.signature)
	if err != nil || len(provided) != sha256.Size || !hmac.Equal(expected, provided) {
		return S3User{}, nil, v4Error(http.StatusForbidden, "SignatureDoesNotMatch", "The request signature does not match.")
	}
	return user, &V4SigningInfo{
		SigningKey: key, Scope: credentials.scope, AmzDate: credentials.amzDate,
		SeedSignature: hex.EncodeToString(provided), PayloadHash: payloadHash,
		Streaming: strings.HasPrefix(payloadHash, "STREAMING-"),
		Trailer:   strings.HasSuffix(payloadHash, "-TRAILER"), Presigned: credentials.presigned,
	}, nil
}

func parseV4Credentials(r *http.Request, query url.Values) (v4Credentials, error) {
	var c v4Credentials
	var credential string
	_, hasQueryToken := query["X-Amz-Security-Token"]
	hasHeaderToken := len(headerValues(r, "x-amz-security-token")) != 0 || len(headerValues(r, "x-amz-s3session-token")) != 0
	if hasQueryToken || hasHeaderToken {
		return c, v4Error(http.StatusForbidden, "InvalidToken", "Session tokens are not supported for configured static credentials.")
	}
	authorizations := headerValues(r, "authorization")
	if len(authorizations) > 1 {
		return c, v4Error(http.StatusBadRequest, "InvalidRequest", "Specify only one authorization header.")
	}
	if hasV4Query(r) {
		if len(authorizations) != 0 {
			return c, v4Error(http.StatusBadRequest, "InvalidRequest", "Header and query authentication cannot be combined.")
		}
		for name := range v4AuthQueryNames {
			if values, ok := query[name]; ok && len(values) != 1 {
				return c, v4Error(http.StatusBadRequest, "InvalidRequest", "Authentication query parameters must appear once.")
			}
		}
		if query.Get("X-Amz-Algorithm") != signV4Algorithm {
			return c, v4Error(http.StatusBadRequest, "InvalidRequest", "AWS4-HMAC-SHA256 query authentication is required.")
		}
		credential = query.Get("X-Amz-Credential")
		c.amzDate = query.Get("X-Amz-Date")
		c.signedHeaders = query.Get("X-Amz-SignedHeaders")
		c.signature = query.Get("X-Amz-Signature")
		c.presigned = true
		expires := query.Get("X-Amz-Expires")
		var err error
		c.expires, err = strconv.ParseInt(expires, 10, 64)
		if err != nil || !decimalDigits(expires) || c.expires < 1 || c.expires > v4MaxExpires {
			return c, v4Error(http.StatusBadRequest, "AuthorizationQueryParametersError", "X-Amz-Expires must be between 1 and 604800 seconds.")
		}
	} else {
		if len(authorizations) != 1 {
			return c, v4Error(http.StatusForbidden, "AccessDenied", "Authentication is required.")
		}
		algorithm, fields, ok := strings.Cut(strings.TrimSpace(authorizations[0]), " ")
		if !ok || algorithm != signV4Algorithm {
			return c, v4Error(http.StatusBadRequest, "InvalidRequest", "AWS4-HMAC-SHA256 authentication is required.")
		}
		parts := make(map[string]string)
		for _, field := range strings.Split(fields, ",") {
			name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
			if !ok || value == "" || parts[name] != "" {
				return c, malformedV4Authorization()
			}
			if name != "Credential" && name != "SignedHeaders" && name != "Signature" {
				return c, malformedV4Authorization()
			}
			parts[name] = value
		}
		if len(parts) != 3 {
			return c, malformedV4Authorization()
		}
		credential = parts["Credential"]
		c.signedHeaders = parts["SignedHeaders"]
		c.signature = parts["Signature"]
		dates := headerValues(r, "x-amz-date")
		if len(dates) == 1 {
			c.amzDate = dates[0]
		} else {
			return c, v4Error(http.StatusBadRequest, "InvalidRequest", "Specify one x-amz-date header.")
		}
	}
	scope := strings.Split(credential, "/")
	if len(scope) != 5 {
		return c, malformedV4Authorization()
	}
	validIdentity := scope[0] != "" && scope[2] != ""
	validScope := scope[3] == "s3" && scope[4] == "aws4_request"
	if !validIdentity || !validScope || len(scope[1]) != 8 || !decimalDigits(scope[1]) {
		return c, malformedV4Authorization()
	}
	c.accessKey, c.date, c.region = scope[0], scope[1], scope[2]
	c.scope = strings.Join(scope[1:], "/")
	if len(c.signature) != sha256.Size*2 || c.signedHeaders == "" {
		return c, malformedV4Authorization()
	}
	return c, nil
}

func (c v4Credentials) checkTime(now time.Time) error {
	stamp, err := time.Parse(v4TimeFormat, c.amzDate)
	if err != nil || stamp.Format(v4TimeFormat) != c.amzDate {
		return v4Error(http.StatusBadRequest, "AuthorizationHeaderMalformed", "The request date must use YYYYMMDDTHHMMSSZ format.")
	}
	if stamp.Format("20060102") != c.date {
		return v4Error(http.StatusBadRequest, "AuthorizationHeaderMalformed", "The credential date does not match the request date.")
	}
	if stamp.Sub(now) > v4ClockSkew {
		return v4Error(http.StatusForbidden, "RequestTimeTooSkewed", "The request date is too far in the future.")
	}
	if c.presigned {
		if now.After(stamp.Add(time.Duration(c.expires) * time.Second)) {
			return v4Error(http.StatusForbidden, "AccessDenied", "The presigned URL has expired.")
		}
		return nil
	}
	if now.Sub(stamp) > v4ClockSkew {
		return v4Error(http.StatusForbidden, "RequestTimeTooSkewed", "The request date is too far in the past.")
	}
	return nil
}

func canonicalV4Headers(r *http.Request, signed string, query url.Values) (string, error) {
	names := strings.Split(signed, ";")
	signedNames := make(map[string]bool, len(names))
	for i, name := range names {
		if !validV4HeaderName(name) || name != strings.ToLower(name) || (i > 0 && name <= names[i-1]) {
			return "", malformedV4Authorization()
		}
		signedNames[name] = true
	}
	if !signedNames["host"] {
		return "", v4Error(http.StatusBadRequest, "AccessDenied", "The host header must be signed.")
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		requiresSignature := strings.HasPrefix(lower, "x-amz-") && lower != "x-amz-content-sha256"
		if (requiresSignature || lower == "content-md5") && !signedNames[lower] {
			return "", v4Error(http.StatusBadRequest, "AccessDenied", "All x-amz headers and Content-MD5 must be signed.")
		}
	}
	var result strings.Builder
	for _, name := range names {
		var values []string
		switch name {
		case "host":
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}
			if host != "" {
				values = []string{host}
			}
		case "content-length":
			values = headerValues(r, name)
			if len(values) == 0 && r.ContentLength >= 0 {
				values = []string{strconv.FormatInt(r.ContentLength, 10)}
			}
		default:
			values = headerValues(r, name)
		}
		if len(values) == 0 {
			return "", v4Error(http.StatusBadRequest, "AccessDenied", "A signed request header is missing.")
		}
		for i := range values {
			values[i] = signV4TrimAll(values[i])
		}
		value := strings.Join(values, ",")
		for key, queryValues := range query {
			if strings.EqualFold(key, name) && (len(queryValues) != 1 || queryValues[0] != value) {
				return "", v4Error(http.StatusBadRequest, "InvalidRequest", "Signed header and query parameter values conflict.")
			}
		}
		result.WriteString(name + ":" + value + "\n")
	}
	return result.String(), nil
}

func headerValues(r *http.Request, name string) []string {
	values := []string{}
	for key, fields := range r.Header {
		if strings.EqualFold(key, name) {
			values = append(values, fields...)
		}
	}
	return values
}

func validV4HeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func v4PayloadHash(r *http.Request, query url.Values) (string, error) {
	values := headerValues(r, "x-amz-content-sha256")
	if queryValues, ok := query["X-Amz-Content-Sha256"]; ok {
		if len(queryValues) != 1 || len(values) != 0 && (len(values) != 1 || values[0] != queryValues[0]) {
			return "", v4Error(http.StatusBadRequest, "InvalidRequest", "Header and query payload hashes must match and appear once.")
		}
		values = queryValues
	}
	if len(values) == 0 {
		// MinIO's standalone signer and presigned requests use this default.
		return unsignedPayload, nil
	}
	if len(values) != 1 {
		return "", v4Error(http.StatusBadRequest, "InvalidRequest", "Specify only one x-amz-content-sha256 header.")
	}
	value := values[0]
	switch value {
	case unsignedPayload, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", "STREAMING-UNSIGNED-PAYLOAD-TRAILER":
		return value, nil
	}
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size || value != strings.ToLower(value) {
		return "", v4Error(http.StatusBadRequest, "InvalidRequest", "The x-amz-content-sha256 value is not supported.")
	}
	return value, nil
}

func canonicalV4URI(u *url.URL) string {
	path := u.Path
	if path == "" {
		path = "/"
	}
	return encodeV4(path, false)
}

func canonicalV4Query(query url.Values, presigned bool) string {
	type queryPair struct{ name, value string }
	pairs := []queryPair{}
	for name, values := range query {
		if presigned && name == "X-Amz-Signature" {
			continue
		}
		for _, value := range values {
			pairs = append(pairs, queryPair{name: encodeV4(name, true), value: encodeV4(value, true)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].name != pairs[j].name {
			return pairs[i].name < pairs[j].name
		}
		return pairs[i].value < pairs[j].value
	})
	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		encoded = append(encoded, pair.name+"="+pair.value)
	}
	return strings.Join(encoded, "&")
}

func encodeV4(value string, encodeSlash bool) string {
	const hexChars = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := range len(value) {
		c := value[i]
		unreserved := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if unreserved || strings.ContainsRune("-_.~", rune(c)) || c == '/' && !encodeSlash {
			encoded.WriteByte(c)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte(hexChars[c>>4])
			encoded.WriteByte(hexChars[c&15])
		}
	}
	return encoded.String()
}

func v4SigningKey(secret, date, region string) []byte {
	dateKey := sumHMAC([]byte("AWS4"+secret), []byte(date))
	regionKey := sumHMAC(dateKey, []byte(region))
	serviceKey := sumHMAC(regionKey, []byte("s3"))
	return sumHMAC(serviceKey, []byte("aws4_request"))
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func malformedV4Authorization() error {
	return v4Error(http.StatusBadRequest, "AuthorizationHeaderMalformed", "The authorization credential, scope, signed headers, or signature is malformed.")
}

func v4Error(status int, code, message string) error {
	return &V4Error{Status: status, Code: code, Message: message}
}

func writeV4Error(w http.ResponseWriter, r *http.Request, err error) {
	var failure *V4Error
	if errors.As(err, &failure) {
		writeS3Error(w, r, failure.Status, failure.Code, failure.Message)
		return
	}
	writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Unable to authenticate the request payload.")
}
