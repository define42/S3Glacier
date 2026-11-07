package s3

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"glacier/bucket"
	"glacier/prometheus"
	"glacier/shared"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

const (
	TarFilesPerHourHeader = "X-Amz-Meta-Tar-Files-Per-Hour"
	s3Namespace           = "http://s3.amazonaws.com/doc/2006-03-01/"
)

type GetBucketLocation struct {
	XMLName            xml.Name `xml:"LocationConstraint"`
	Xmlns              string   `xml:"xmlns,attr"`
	LocationConstraint string   `xml:",chardata"`
}

type s3Error struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource"`
}

func writeS3XML(w http.ResponseWriter, status int, value any) {
	body, err := xml.Marshal(value)
	if err != nil {
		log.Printf("encode S3 response: %v", err)
		http.Error(w, "Unable to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if _, err := io.WriteString(w, xml.Header+string(body)); err != nil {
		log.Printf("write S3 response: %v", err)
	}
}

func writeS3Error(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		return
	}
	writeS3XML(w, status, s3Error{Code: code, Message: message, Resource: r.URL.Path})
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request, allow string) {
	w.Header().Set("Allow", allow)
	writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "The method is not supported for this resource.")
}

func bucketHeaders(w http.ResponseWriter, b bucket.Bucket) {
	w.Header().Set(TarFilesPerHourHeader, strconv.Itoa(b.TarFilesPerHour))
}

// BucketHandler creates buckets and exposes their immutable storage layout.
func BucketHandler(store *bucket.Store) S3SecurityHandle {
	return func(w http.ResponseWriter, r *http.Request, user S3User) {
		name := mux.Vars(r)["bucket"]
		switch r.Method {
		case http.MethodPut:
			if !user.Write {
				writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Write access is required to create a bucket.")
				return
			}
			if len(r.URL.Query()) != 0 {
				writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Bucket subresources are not supported.")
				return
			}
			values := r.Header.Values(TarFilesPerHourHeader)
			if len(values) != 1 || values[0] == "" {
				writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Specify x-amz-meta-tar-files-per-hour when creating a bucket.")
				return
			}
			count, err := strconv.Atoi(values[0])
			if err != nil {
				writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The TAR files per hour must be an integer.")
				return
			}
			b, err := store.Create(name, count)
			if err != nil {
				switch {
				case errors.Is(err, bucket.ErrExists):
					writeS3Error(w, r, http.StatusConflict, "BucketAlreadyOwnedByYou", "The bucket already exists; its TAR files per hour cannot be changed.")
				case errors.Is(err, bucket.ErrInvalidName):
					writeS3Error(w, r, http.StatusBadRequest, "InvalidBucketName", "The bucket name is invalid.")
				case errors.Is(err, bucket.ErrInvalidTarFiles):
					writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The TAR files per hour is outside the supported range.")
				default:
					log.Printf("create S3 bucket %q: %v", name, err)
					writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Unable to create the bucket.")
				}
				return
			}
			bucketHeaders(w, b)
			w.Header().Set("Location", "/"+b.Name)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet, http.MethodHead:
			if !user.Read {
				writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Read access is required.")
				return
			}
			b, err := store.Get(name)
			if err != nil {
				writeS3Error(w, r, http.StatusNotFound, "NoSuchBucket", "The bucket does not exist.")
				return
			}
			bucketHeaders(w, b)
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.URL.Query().Has("location") && len(r.URL.Query()) == 1 {
				writeS3XML(w, http.StatusOK, GetBucketLocation{Xmlns: s3Namespace})
				return
			}
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Object listing and other bucket subresources are not supported.")
		default:
			methodNotAllowed(w, r, "GET, HEAD, PUT")
		}
	}
}

// ObjectHandler serves objects inside the bucket resolved from the request path.
// S3Security authenticates the request before this handler is invoked.
func ObjectHandler(store *bucket.Store) S3SecurityHandle {
	return func(w http.ResponseWriter, r *http.Request, user S3User) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			if !user.Read {
				writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Read access is required.")
				return
			}
		case http.MethodPut:
			if !user.Write {
				writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Write access is required.")
				return
			}
		default:
			methodNotAllowed(w, r, "GET, HEAD, PUT")
			return
		}

		vars := mux.Vars(r)
		b, err := store.Get(vars["bucket"])
		if err != nil {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchBucket", "The bucket does not exist.")
			return
		}
		for name := range r.URL.Query() {
			if name != "parse" {
				writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Object subresources are not supported.")
				return
			}
		}
		if _, _, err := shared.GetBucketContainerFile(b, vars["id"]); err != nil {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The object key must contain a supported time UUID.")
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Last-Modified", shared.GetFileTime(vars["id"]).UTC().Format(http.TimeFormat))
			shared.GetBucketFile(&objectResponseWriter{ResponseWriter: w, request: r}, r, b)
			return
		}

		prometheus.RawUploadProcessed.Inc()
		defer r.Body.Close()
		fileBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeS3Error(w, r, http.StatusBadRequest, "IncompleteBody", "Unable to read the object body.")
			return
		}
		hash := md5.Sum(fileBytes)
		if supplied := r.Header.Get("Content-MD5"); supplied != "" {
			expected, err := base64.StdEncoding.DecodeString(supplied)
			if err != nil || len(expected) != md5.Size {
				writeS3Error(w, r, http.StatusBadRequest, "InvalidDigest", "The Content-MD5 header is invalid.")
				return
			}
			if !bytes.Equal(expected, hash[:]) {
				writeS3Error(w, r, http.StatusBadRequest, "BadDigest", "The Content-MD5 header does not match the object body.")
				return
			}
		}
		if _, _, err := shared.UploadToBucket(r, b, vars["id"], fileBytes); err != nil {
			log.Printf("upload S3 object in bucket %q: %v", b.Name, err)
			writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Unable to store the object.")
			return
		}
		w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
		w.WriteHeader(http.StatusOK)
	}
}

// objectResponseWriter translates shared read errors without buffering object data.
type objectResponseWriter struct {
	http.ResponseWriter
	request   *http.Request
	hasStatus bool
	hasError  bool
}

func (w *objectResponseWriter) WriteHeader(status int) {
	if w.hasStatus {
		return
	}
	w.hasStatus = true
	if status < http.StatusBadRequest {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.hasError = true
	w.Header().Del("Content-Length")
	w.Header().Del("Last-Modified")
	code, message := "InternalError", "Unable to read the object."
	switch status {
	case http.StatusBadRequest:
		code, message = "InvalidArgument", "The object key is invalid."
	case http.StatusNotFound:
		code, message = "NoSuchKey", "The object does not exist."
	case http.StatusForbidden:
		code, message = "AccessDenied", "Access to the object is denied."
	}
	writeS3Error(w.ResponseWriter, w.request, status, code, message)
}

func (w *objectResponseWriter) Write(data []byte) (int, error) {
	if !w.hasStatus {
		w.WriteHeader(http.StatusOK)
	}
	if w.hasError || w.request.Method == http.MethodHead {
		return len(data), nil
	}
	return w.ResponseWriter.Write(data)
}

type listedBucket struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type listAllMyBucketsResult struct {
	XMLName xml.Name       `xml:"ListAllMyBucketsResult"`
	Xmlns   string         `xml:"xmlns,attr"`
	Buckets []listedBucket `xml:"Buckets>Bucket"`
}

// ListBuckets returns the buckets available on this server to an authenticated reader.
func ListBuckets(store *bucket.Store) S3SecurityHandle {
	return func(w http.ResponseWriter, r *http.Request, user S3User) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r, "GET")
			return
		}
		if !user.Read {
			writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Read access is required.")
			return
		}
		result := listAllMyBucketsResult{Xmlns: s3Namespace, Buckets: make([]listedBucket, 0)}
		for _, b := range store.List() {
			result.Buckets = append(result.Buckets, listedBucket{Name: b.Name, CreationDate: b.CreatedAt.UTC().Format(time.RFC3339)})
		}
		writeS3XML(w, http.StatusOK, result)
	}
}
