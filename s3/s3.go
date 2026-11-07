package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
)

const Authorization = "Authorization"

type S3User struct {
	SecretAccessKey string
	Write           bool
	Read            bool
}

type S3Users struct {
	mu sync.RWMutex
	m  map[string]S3User
}

var s3UsersList = &S3Users{m: make(map[string]S3User)}

// ResetS3Users removes credentials from an earlier server initialization.
func ResetS3Users() {
	s3UsersList.mu.Lock()
	defer s3UsersList.mu.Unlock()
	s3UsersList.m = make(map[string]S3User)
}

func AddS3User(accessKeyID string, secretAccessKey string, write bool, read bool) {
	s3UsersList.mu.Lock()
	defer s3UsersList.mu.Unlock()
	s3UsersList.m[accessKeyID] = S3User{SecretAccessKey: secretAccessKey, Write: write, Read: read}
}

func AddS3UserWrite(users string) {
	addS3Users(users, true)
}

func AddS3UserReadOnly(users string) {
	addS3Users(users, false)
}

func addS3Users(users string, write bool) {
	for _, user := range strings.Split(users, ";") {
		key, secret, ok := strings.Cut(strings.TrimSpace(user), "=")
		if ok && key != "" && secret != "" {
			AddS3User(key, secret, write, true)
		}
	}
}

type S3SecurityHandle func(w http.ResponseWriter, r *http.Request, user S3User)

func S3Security(next S3SecurityHandle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authFields := strings.Fields(r.Header.Get(Authorization))
		if len(authFields) == 0 {
			writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Authentication is required.")
			return
		}
		if len(authFields) != 2 || authFields[0] != signV2Algorithm {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidRequest", "AWS Signature Version 2 authentication is required.")
			return
		}
		accessKey, requestSignature, ok := strings.Cut(authFields[1], ":")
		if !ok || accessKey == "" || requestSignature == "" {
			writeS3Error(w, r, http.StatusBadRequest, "AuthorizationHeaderMalformed", "The authorization header is malformed.")
			return
		}

		s3UsersList.mu.RLock()
		user, ok := s3UsersList.m[accessKey]
		s3UsersList.mu.RUnlock()
		if !ok {
			writeS3Error(w, r, http.StatusForbidden, "InvalidAccessKeyId", "The access key does not exist.")
			return
		}

		hm := hmac.New(sha1.New, []byte(user.SecretAccessKey))
		_, _ = hm.Write([]byte(StringToSignV2(*r, false)))
		signature := base64.StdEncoding.EncodeToString(hm.Sum(nil))
		if !hmac.Equal([]byte(signature), []byte(requestSignature)) {
			writeS3Error(w, r, http.StatusForbidden, "SignatureDoesNotMatch", "The request signature does not match.")
			return
		}
		next(w, r, user)
	})
}
