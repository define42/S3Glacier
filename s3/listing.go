package s3

import (
	"context"
	"encoding/xml"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"glacier/config"
	"glacier/shared"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxListedObjects = 1000

type listOwner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

func archiveOwner() listOwner { return listOwner{ID: "s3glacier", DisplayName: "s3glacier"} }

type listedObject struct {
	Key          string     `xml:"Key"`
	LastModified string     `xml:"LastModified"`
	ETag         string     `xml:"ETag,omitempty"`
	Size         int64      `xml:"Size"`
	StorageClass string     `xml:"StorageClass"`
	Owner        *listOwner `xml:"Owner,omitempty"`
}

type listedCommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type listBucketResult struct {
	XMLName               xml.Name             `xml:"ListBucketResult"`
	Xmlns                 string               `xml:"xmlns,attr"`
	Name                  string               `xml:"Name"`
	Prefix                string               `xml:"Prefix"`
	Delimiter             string               `xml:"Delimiter,omitempty"`
	MaxKeys               int                  `xml:"MaxKeys"`
	KeyCount              int                  `xml:"KeyCount"`
	IsTruncated           bool                 `xml:"IsTruncated"`
	EncodingType          string               `xml:"EncodingType,omitempty"`
	StartAfter            string               `xml:"StartAfter,omitempty"`
	ContinuationToken     string               `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string               `xml:"NextContinuationToken,omitempty"`
	Contents              []listedObject       `xml:"Contents"`
	CommonPrefixes        []listedCommonPrefix `xml:"CommonPrefixes"`
}

type listQuery struct {
	prefix, delimiter, after string
	startAfter, token        string
	maxKeys                  int
	encodeURL, fetchOwner    bool
	extended                 bool
}

type listQueryError struct {
	code, message string
	status        int
}

func (e *listQueryError) Error() string { return e.message }

func invalidListArgument(message string) error {
	return &listQueryError{code: "InvalidArgument", message: message, status: http.StatusBadRequest}
}

func parseListQuery(values url.Values) (listQuery, error) {
	q := listQuery{maxKeys: maxListedObjects}
	for name, values := range values {
		if len(values) != 1 {
			return q, invalidListArgument("Specify each listing parameter only once.")
		}
		switch name {
		case "list-type", "prefix", "delimiter", "max-keys", "start-after", "continuation-token", "encoding-type", "fetch-owner":
		default:
			return q, &listQueryError{code: "NotImplemented", message: "The requested listing option is not supported.", status: http.StatusNotImplemented}
		}
	}
	if values.Get("list-type") != "2" {
		return q, invalidListArgument("The supported listing version is list-type=2.")
	}
	if values.Has("max-keys") {
		value := values.Get("max-keys")
		if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return q, invalidListArgument("max-keys must be an integer from 0 through 1000.")
		}
		count, err := strconv.Atoi(value)
		if err != nil || count > maxListedObjects {
			return q, invalidListArgument("max-keys must be an integer from 0 through 1000.")
		}
		q.maxKeys = count
	}
	if values.Has("encoding-type") {
		if values.Get("encoding-type") != "url" {
			return q, invalidListArgument("The supported encoding-type is url.")
		}
		q.encodeURL = true
	}
	if values.Has("fetch-owner") {
		switch values.Get("fetch-owner") {
		case "true":
			q.fetchOwner = true
		case "false":
		default:
			return q, invalidListArgument("fetch-owner must be true or false.")
		}
	}
	q.prefix, q.delimiter = values.Get("prefix"), values.Get("delimiter")
	q.startAfter, q.token = values.Get("start-after"), values.Get("continuation-token")
	q.after = q.startAfter
	if values.Has("continuation-token") && q.token == "" {
		return q, invalidListArgument("The continuation token is invalid.")
	}
	for _, value := range []string{q.prefix, q.delimiter, q.startAfter} {
		if !utf8.ValidString(value) {
			return q, invalidListArgument("Listing parameters must be valid UTF-8.")
		}
		if !q.encodeURL && strings.IndexFunc(value, invalidXMLCharacter) >= 0 {
			return q, invalidListArgument("Use encoding-type=url for characters that cannot appear in XML.")
		}
	}
	return q, nil
}

func invalidXMLCharacter(r rune) bool {
	return !(r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= 0x10ffff)
}

func listObjectsV2(w http.ResponseWriter, r *http.Request, b bucket.Bucket, user S3User) {
	q, err := parseListQuery(s3OperationQuery(r))
	if err != nil {
		if argument, ok := errors.AsType[*listQueryError](err); ok {
			writeS3Error(w, r, argument.status, argument.code, argument.message)
		}
		return
	}
	if expected := r.Header.Get("X-Amz-Expected-Bucket-Owner"); expected != "" && expected != archiveOwner().ID {
		writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "The expected bucket owner does not match.")
		return
	}
	if r.Header.Get("X-Amz-Optional-Object-Attributes") != "" || r.Header.Get("X-Amz-Request-Payer") != "" {
		writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "The requested listing option is not supported.")
		return
	}
	q.extended = config.Settings.Get(config.EXTEND_LIFE_SUPPORT) == "true"
	if q.token != "" {
		q.after, err = decodeListToken(q.token, b, q, user.SecretAccessKey)
		if err != nil {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The continuation token is invalid for this request.")
			return
		}
	}
	var entries []archive.ListEntry
	if q.maxKeys > 0 {
		entries, err = listBucketEntries(r.Context(), archive.Default, b, q)
		if err != nil {
			switch {
			case errors.Is(err, archive.ErrBusy):
				w.Header().Set("Retry-After", "1")
				writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "An archive is busy; try again.")
			case errors.Is(err, archive.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
				writeS3Error(w, r, http.StatusServiceUnavailable, "ServiceUnavailable", "An archive is unavailable.")
			default:
				log.Printf("list S3 objects in bucket %q: %v", b.Name, err)
				writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Unable to list objects.")
			}
			return
		}
	}
	result := listBucketResult{Xmlns: s3Namespace, Name: b.Name, Prefix: q.prefix, Delimiter: q.delimiter,
		MaxKeys: q.maxKeys, StartAfter: q.startAfter, ContinuationToken: q.token}
	if len(entries) > q.maxKeys {
		result.IsTruncated = true
		entries = entries[:q.maxKeys]
		result.NextContinuationToken, err = encodeListToken(entries[len(entries)-1].Key, b, q, user.SecretAccessKey)
		if err != nil {
			writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Unable to create a continuation token.")
			return
		}
	}
	result.KeyCount = len(entries)
	owner := archiveOwner()
	for _, entry := range entries {
		if entry.CommonPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, listedCommonPrefix{Prefix: entry.Key})
			continue
		}
		object := listedObject{Key: entry.Key, Size: entry.Size, StorageClass: "STANDARD",
			LastModified: shared.GetFileTime(entry.Key).UTC().Format("2006-01-02T15:04:05.000Z")}
		if entry.ETag != "" {
			object.ETag = `"` + entry.ETag + `"`
		}
		if q.fetchOwner {
			object.Owner = &owner
		}
		result.Contents = append(result.Contents, object)
	}
	if q.encodeURL {
		result.EncodingType = "url"
		result.Prefix, result.Delimiter, result.StartAfter = encodeV4(result.Prefix, true), encodeV4(result.Delimiter, true), encodeV4(result.StartAfter, true)
		for i := range result.Contents {
			result.Contents[i].Key = encodeV4(result.Contents[i].Key, true)
		}
		for i := range result.CommonPrefixes {
			result.CommonPrefixes[i].Prefix = encodeV4(result.CommonPrefixes[i].Prefix, true)
		}
	}
	writeS3XML(w, http.StatusOK, result)
}
