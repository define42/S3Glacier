package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Authorization is the HTTP header used for V2 and V4 header authentication.
const Authorization = "Authorization"

// S3User grants read and write access across the server's buckets.
// SecretAccessKey is used to verify signatures and must remain private.
type S3User struct {
	SecretAccessKey string
	Write           bool
	Read            bool
}

// S3Users is the synchronized credential registry used by this package.
// Manage the package registry through the AddS3User functions and ResetS3Users.
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

// AddS3User adds or replaces a static access key and its server-wide permissions.
func AddS3User(accessKeyID string, secretAccessKey string, write bool, read bool) {
	s3UsersList.mu.Lock()
	defer s3UsersList.mu.Unlock()
	s3UsersList.m[accessKeyID] = S3User{SecretAccessKey: secretAccessKey, Write: write, Read: read}
}

// AddS3UserWrite loads semicolon-separated access-key=secret pairs with read
// and write permission. Empty or malformed pairs are ignored.
func AddS3UserWrite(users string) {
	addS3Users(users, true)
}

// AddS3UserReadOnly loads semicolon-separated access-key=secret pairs with read
// permission only. A matching access key replaces an earlier registration.
func AddS3UserReadOnly(users string) {
	addS3Users(users, false)
}

func addS3Users(users string, write bool) {
	for user := range strings.SplitSeq(users, ";") {
		key, secret, ok := strings.Cut(strings.TrimSpace(user), "=")
		if ok && key != "" && secret != "" {
			AddS3User(key, secret, write, true)
		}
	}
}

// S3SecurityHandle handles a request whose S3 identity has been authenticated.
// Resource handlers still enforce the permissions required for their operation.
type S3SecurityHandle func(w http.ResponseWriter, r *http.Request, user S3User)

// S3Security authenticates V2 header signatures or V4 header/query signatures.
// V4 bodies are verified before next is invoked; failures use S3 XML errors.
func S3Security(next S3SecurityHandle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(headerValues(r, "authorization")) > 1 {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidRequest", "Specify only one authorization header.")
			return
		}
		if strings.HasPrefix(strings.TrimSpace(r.Header.Get(Authorization)), "AWS4-") || hasV4Query(r) {
			user, info, err := verifyV4(r, time.Now().UTC())
			if err != nil {
				writeV4Error(w, r, err)
				return
			}
			switch r.Method {
			case http.MethodPut:
				if !user.Write {
					writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Write access is required.")
					return
				}
			case http.MethodGet, http.MethodHead:
				if !user.Read {
					writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Read access is required.")
					return
				}
			default:
				methodNotAllowed(w, r, "GET, HEAD, PUT")
				return
			}
			r = withV4Info(r, info)
			if err := VerifyV4Payload(r, info); err != nil {
				writeV4Error(w, r, err)
				return
			}
			next(w, r, user)
			return
		}
		authFields := strings.Fields(r.Header.Get(Authorization))
		if len(authFields) == 0 {
			writeS3Error(w, r, http.StatusForbidden, "AccessDenied", "Authentication is required.")
			return
		}
		if len(authFields) != 2 || authFields[0] != signV2Algorithm {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidRequest", "AWS Signature Version 2 or 4 authentication is required.")
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
