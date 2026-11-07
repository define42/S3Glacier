package main

import (
	"glacier/bucket"
	"glacier/prometheus"
	"glacier/shared"
	"html/template"
	"io"
	"net/http"

	"github.com/gorilla/mux"
)

type uploadResult struct {
	ID     string
	Bucket string
	URL    string
}

var uploadResults = template.Must(template.New("uploads").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Uploaded objects</title>
<link href="/static/bootstrap.css" rel="stylesheet"></head><body class="container py-4">
<h1>Uploaded objects</h1><p>Use the read token in the download form if reading is protected.</p>
<table class="table"><thead><tr><th>Bucket</th><th>Object ID</th></tr></thead><tbody>
{{range .}}<tr><td>{{.Bucket}}</td><td><a href="{{.URL}}">{{.ID}}</a></td></tr>{{end}}
</tbody></table><a href="/">Back to archive</a></body></html>`))

func rawUpload(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !shared.AuthorizeWrite(w, r) {
			return
		}
		b, ok := requestBucket(w, r, store)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		if _, _, err := shared.GetBucketContainerFile(b, id); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prometheus.RawUploadProcessed.Inc()
		defer r.Body.Close()
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read upload", http.StatusBadRequest)
			return
		}
		id, _, err = shared.UploadToBucket(r, b, id, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeUploadResults(w, []uploadResult{{ID: id, Bucket: b.Name, URL: shared.ObjectURL(b.Name, id, "")}})
	}
}

func uploadFile(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, "Invalid multipart upload", http.StatusBadRequest)
			return
		}
		defer r.MultipartForm.RemoveAll()
		if !shared.AuthorizeWrite(w, r) {
			return
		}
		b, ok := requestBucket(w, r, store)
		if !ok {
			return
		}
		files := r.MultipartForm.File["file"]
		if len(files) == 0 {
			http.Error(w, "Select at least one file", http.StatusBadRequest)
			return
		}
		results := make([]uploadResult, 0, len(files))
		for _, header := range files {
			id := header.Filename
			if r.URL.Query().Get("newuuid") != "" {
				id = shared.GenerateTimeUUID()
			}
			if _, _, err := shared.GetBucketContainerFile(b, id); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			file, err := header.Open()
			if err != nil {
				http.Error(w, "Unable to open upload", http.StatusInternalServerError)
				return
			}
			data, err := io.ReadAll(file)
			_ = file.Close()
			if err != nil {
				http.Error(w, "Unable to read upload", http.StatusBadRequest)
				return
			}
			prometheus.RawUploadProcessed.Inc()
			id, _, err = shared.UploadToBucket(r, b, id, data)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			results = append(results, uploadResult{ID: id, Bucket: b.Name, URL: shared.ObjectURL(b.Name, id, r.Form.Get("read_token"))})
		}
		writeUploadResults(w, results)
	}
}

func downloadFile(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !shared.AuthorizeRead(w, r) {
			return
		}
		b, ok := requestBucket(w, r, store)
		if ok {
			shared.GetBucketFile(w, r, b)
		}
	}
}

func writeUploadResults(w http.ResponseWriter, results []uploadResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = uploadResults.Execute(w, results)
}
