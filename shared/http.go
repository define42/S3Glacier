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

// RequestToken accepts bearer credentials and the existing URL/form tokens.
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

func AuthorizeRead(w http.ResponseWriter, r *http.Request) bool {
	return authorizeToken(w, r, config.READ_TOKEN)
}

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

// RequestBucket selects data when the request does not specify a bucket.
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

func ObjectURL(name, id, token string) string {
	path := "/buckets/" + url.PathEscape(name) + "/get/" + url.PathEscape(id)
	if token != "" {
		path += "?" + url.Values{"token": {token}}.Encode()
	}
	return path
}
