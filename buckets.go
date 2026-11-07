package main

import (
	"encoding/json"
	"errors"
	"glacier/bucket"
	"glacier/shared"
	"io"
	"net/http"
)

func manageBuckets(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if shared.AuthorizeRead(w, r) {
				writeJSON(w, http.StatusOK, store.List())
			}
		case http.MethodPost:
			if !shared.AuthorizeWrite(w, r) {
				return
			}
			var input struct {
				Name            string `json:"name"`
				TarFilesPerHour int    `json:"tar_files_per_hour"`
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			defer r.Body.Close()
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				http.Error(w, "Provide name and tar_files_per_hour as JSON", http.StatusBadRequest)
				return
			}
			if err := decoder.Decode(new(any)); err != io.EOF {
				http.Error(w, "Expected one JSON object", http.StatusBadRequest)
				return
			}
			b, err := store.Create(input.Name, input.TarFilesPerHour)
			if err != nil {
				writeBucketError(w, err)
				return
			}
			w.Header().Set("Location", "/buckets/"+b.Name)
			writeJSON(w, http.StatusCreated, b)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "Use POST to create a bucket; existing configurations are immutable", http.StatusMethodNotAllowed)
		}
	}
}

func inspectBucket(store *bucket.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Bucket configurations cannot be changed or deleted", http.StatusMethodNotAllowed)
			return
		}
		if !shared.AuthorizeRead(w, r) {
			return
		}
		b, ok := requestBucket(w, r, store)
		if !ok {
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(w, http.StatusOK, b)
	}
}

func requestBucket(w http.ResponseWriter, r *http.Request, store *bucket.Store) (bucket.Bucket, bool) {
	b, err := store.Get(shared.RequestBucket(r))
	if err != nil {
		writeBucketError(w, err)
		return bucket.Bucket{}, false
	}
	return b, true
}

func writeBucketError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, bucket.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, bucket.ErrExists):
		status = http.StatusConflict
	case errors.Is(err, bucket.ErrInvalidName), errors.Is(err, bucket.ErrInvalidTarFiles):
		status = http.StatusBadRequest
	}
	http.Error(w, err.Error(), status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func querySuffix(r *http.Request) string {
	if r.URL.RawQuery != "" {
		return "?" + r.URL.RawQuery
	}
	return ""
}
