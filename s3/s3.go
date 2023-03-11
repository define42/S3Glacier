package s3

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"glacier/config"
	"glacier/prometheus"
	"glacier/shared"
	"io/ioutil"
	"net/http"
	"time"
	        "crypto/hmac"
        "crypto/sha1"
        "encoding/base64"
	"net/http/httputil"
	"strings"
	"github.com/gorilla/mux"
)

type GetBucketLocation struct {
	XMLName            xml.Name `xml:"LocationConstraint"`
	Xmlns              string   `xml:"xmlns,attr"`
	LocationConstraint string   `xml:",chardata"`
}

func xmlEncoder(w http.ResponseWriter) *xml.Encoder {
	w.Write([]byte(xml.Header))
	w.Header().Set("Content-Type", "application/xml")

	xe := xml.NewEncoder(w)
	xe.Indent("", "  ")
	return xe
}

func S3Bucket(w http.ResponseWriter, r *http.Request) {
	dump, _ := httputil.DumpRequest(r, true)
	fmt.Println(string(dump))
	result := GetBucketLocation{
		Xmlns:              "http://s3.amazonaws.com/doc/2006-03-01/",
		LocationConstraint: "",
	}
	xmlEncoder(w).Encode(result)
}

func formatHeaderTime(t time.Time) string {
	tc := t.In(time.UTC)
	return tc.Format("Mon, 02 Jan 2006 15:04:05") + " GMT"
}

const (
	Authorization = "Authorization"
)

type S3SecurityHandle func(w http.ResponseWriter, r *http.Request)

func S3Security(next S3SecurityHandle) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//        dump, _ := httputil.DumpRequest(r, true)
//        fmt.Println(string(dump))
        stringToSign := StringToSignV2(*r, false)

        v2Auth := r.Header.Get(Authorization)
        if v2Auth == "" {
		w.WriteHeader(http.StatusInternalServerError)
		return
        }
        if !strings.HasPrefix(v2Auth, signV2Algorithm) {
		w.WriteHeader(http.StatusInternalServerError)
		return
        }

        authFields := strings.Split(v2Auth, " ")
        if len(authFields) != 2 {
		w.WriteHeader(http.StatusInternalServerError)
		return
        }
        keySignFields := strings.Split(strings.TrimSpace(authFields[1]), ":")
        if len(keySignFields) != 2 {
		w.WriteHeader(http.StatusInternalServerError)
		return
        }

        secretAccessKey := "sssssssssssssssssssssssssssssssssssssssssss"
        hm := hmac.New(sha1.New, []byte(secretAccessKey))
        hm.Write([]byte(stringToSign))

        // Calculate signature.
        signature := base64.StdEncoding.EncodeToString(hm.Sum(nil))
        fmt.Println("signature:", signature, "keySignFields[0]:", keySignFields[0], " keySignFields[1]:", keySignFields[1])
        if signature == keySignFields[1] {
		next(w, r)
        }else{
		w.WriteHeader(http.StatusInternalServerError)
	}
	})
}

func S3Handler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		fmt.Println("id is missing in parameters")
	}
	switch r.Method {
	case "GET":
		{
			w.Header().Set("Last-Modified", formatHeaderTime(shared.GetFileTime(id)))
			shared.GetFile(w, r)
		}
	case "PUT":
		{
			prometheus.RawUploadProcessed.Inc()
			fileBytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, err)
				return
			}
			defer r.Body.Close()

			token, ok := vars["token"]
			if !ok {
				fmt.Println("token is missing in parameters")
			}
			fmt.Println(token)
			if config.Settings.Has(config.WRITE_TOKEN) && token != config.Settings.Get(config.WRITE_TOKEN) {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintln(w, "Access forbidden")
				return
			}

			_, _, err = shared.SharedUpload(r, token, id, fileBytes)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, err)
				return
			}
			hash := md5.Sum(fileBytes)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
		}
	}
}
