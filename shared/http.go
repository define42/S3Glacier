package shared

import (
	"crypto/subtle"
	"glacier/bucket"
	"glacier/config"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"
)

// RequestToken selects credentials in order: a Bearer Authorization header,
// mux "token" variable, token query parameter, then an already parsed form.
// It does not parse the request body.
func RequestToken(r *http.Request) string {
	if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return token
	}
	if token := mux.Vars(r)["token"]; token != "" {
		return token
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}
	return r.Form.Get("token")
}

// AuthorizeRead enforces READ_TOKEN for HTTP and browser routes. An empty setting
// permits access; a mismatch writes HTTP 403 and returns false. S3 handlers use
// their own authenticated user permissions instead.
func AuthorizeRead(w http.ResponseWriter, r *http.Request) bool {
	return authorizeToken(w, r, config.READ_TOKEN)
}

// AuthorizeWrite enforces WRITE_TOKEN for HTTP and browser routes. An empty
// setting permits access; a mismatch writes HTTP 403 and returns false.
func AuthorizeWrite(w http.ResponseWriter, r *http.Request) bool {
	return authorizeToken(w, r, config.WRITE_TOKEN)
}

func authorizeToken(w http.ResponseWriter, r *http.Request, setting string) bool {
	expected := config.Settings.Get(setting)
	if expected != "" && subtle.ConstantTimeCompare([]byte(RequestToken(r)), []byte(expected)) != 1 {
		http.Error(w, "Access forbidden", http.StatusForbidden)
		return false
	}
	return true
}

// RequestBucket selects the mux "bucket" variable, bucket query parameter, or
// already parsed bucket form value, in that order. It defaults to "data" and
// does not validate the name or verify that the bucket exists.
func RequestBucket(r *http.Request) string {
	if name := mux.Vars(r)["bucket"]; name != "" {
		return name
	}
	if name := r.URL.Query().Get("bucket"); name != "" {
		return name
	}
	if name := r.Form.Get("bucket"); name != "" {
		return name
	}
	return bucket.DefaultName
}

// ObjectURL builds an escaped bucket-scoped HTTP download URL. A nonempty token
// is carried in its query string for browser navigation.
func ObjectURL(name, id, token string) string {
	path := "/buckets/" + url.PathEscape(name) + "/get/" + url.PathEscape(id)
	if token != "" {
		path += "?" + url.Values{"token": {token}}.Encode()
	}
	return path
}
