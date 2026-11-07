//go:build integration

package main

import (
	"bytes"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"glacier/prometheus"
	"glacier/s3"
	"glacier/shared"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestUploadsRejectCheckpointPublicationFailure(t *testing.T) {
	// Server settings and the archive coordinator are process globals, so these
	// cases must not run in parallel.
	for _, protocol := range []string{"HTTP", "S3"} {
		t.Run(protocol, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "data")
			t.Setenv("DATA_FOLDER", root)
			t.Setenv("READ_TOKEN", "read-secret")
			t.Setenv("WRITE_TOKEN", "write-secret")
			t.Setenv("S3_READ_ONLY_USERS", "")
			t.Setenv("S3_READ_WRITE_USERS", "writer=secret")
			t.Setenv("EXTEND_LIFE_SUPPORT", "false")
			previousStore := archive.Default
			archive.Default = archive.NewStore()
			t.Cleanup(func() { archive.Default = previousStore })
			router, err := NewServer()
			if err != nil {
				t.Fatal(err)
			}
			response := bucketRequest(t, router, http.MethodPost, "/buckets", "write-secret", []byte(`{"name":"durable","tar_files_per_hour":1}`))
			if response.Code != http.StatusCreated {
				t.Fatalf("create bucket: %d %s", response.Code, response.Body.String())
			}
			originalID := "20261107-1200-4000-8000-000000000001"
			pendingID := "20261107-1200-4000-8000-000000000002"
			original := []byte("acknowledged original content")
			response = bucketRequest(t, router, http.MethodPut, "/buckets/durable/rawupload/"+originalID, "write-secret", original)
			if response.Code != http.StatusOK {
				t.Fatalf("initial upload: %d %s", response.Code, response.Body.String())
			}
			b := bucket.Bucket{Name: "durable", TarFilesPerHour: 1, Path: filepath.Join(root, "buckets", "durable")}
			path, _, err := shared.GetBucketContainerFile(b, originalID)
			if err != nil {
				t.Fatal(err)
			}
			pendingPath, _, err := shared.GetBucketContainerFile(b, pendingID)
			if err != nil || pendingPath != path {
				t.Fatalf("pending upload must share the original archive: path=%q err=%v", pendingPath, err)
			}
			beforeArchive := durabilityReadFile(t, path)
			beforeCheckpoint := durabilityReadFile(t, archive.CommitPath(path))
			beforeCompleted := durabilityCompletedUploads(t)
			directory := filepath.Dir(path)
			info, err := os.Stat(directory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(directory, info.Mode().Perm()); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chmod(directory, 0500); err != nil {
				t.Fatal(err)
			}
			// A real directory permission failure blocks checkpoint publication
			// while allowing the existing writable TAR to receive its append.
			probe, err := os.CreateTemp(directory, ".permission-probe-*")
			if err == nil {
				name := probe.Name()
				if err := probe.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				t.Skip("directory permissions do not prevent creation for this user or filesystem")
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("permission probe: %v", err)
			}
			pending := bytes.Repeat([]byte("unacknowledged pending content\n"), 40)
			if protocol == "HTTP" {
				response = bucketRequest(t, router, http.MethodPut, "/buckets/durable/rawupload/"+pendingID, "write-secret", pending)
			} else {
				request := httptest.NewRequest(http.MethodPut, "/durable/"+pendingID, bytes.NewReader(pending))
				request = s3.SignV2(*request, "writer", "secret", false)
				response = httptest.NewRecorder()
				router.ServeHTTP(response, request)
			}
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("upload whose checkpoint could not be published: %d %s", response.Code, response.Body.String())
			}
			if response.Header().Get("ETag") != "" {
				t.Fatal("failed upload returned a successful S3 ETag")
			}
			if got := durabilityCompletedUploads(t); got != beforeCompleted {
				t.Fatalf("failed upload incremented completed counter: got %v, want %v", got, beforeCompleted)
			}
			if got := durabilityReadFile(t, archive.CommitPath(path)); !bytes.Equal(got, beforeCheckpoint) {
				t.Fatal("failed checkpoint publication changed the committed boundary")
			}
			if got := durabilityReadFile(t, path); len(got) <= len(beforeArchive) {
				t.Fatal("fixture did not reach publication failure after appending to the TAR")
			}
			reader, err := archive.Default.Open(t.Context(), path)
			if reader != nil {
				reader.Close()
			}
			if reader != nil || !errors.Is(err, archive.ErrUnavailable) {
				t.Fatalf("failed upload did not quarantine readers: reader=%v err=%v", reader, err)
			}
			if err := os.Chmod(directory, info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
			archive.Default = archive.NewStore()
			response = bucketRequest(t, router, http.MethodGet, "/buckets/durable/get/"+originalID, "read-secret", nil)
			if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), original) {
				t.Fatalf("original object after recovery: %d %q", response.Code, response.Body.Bytes())
			}
			response = bucketRequest(t, router, http.MethodGet, "/buckets/durable/get/"+pendingID, "read-secret", nil)
			if response.Code != http.StatusNotFound {
				t.Fatalf("uncommitted object became visible: %d %s", response.Code, response.Body.String())
			}
			if got := durabilityReadFile(t, path); !bytes.Equal(got, beforeArchive) {
				t.Fatal("recovery did not restore the original committed archive")
			}
		})
	}
}

func durabilityReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func durabilityCompletedUploads(t *testing.T) float64 {
	t.Helper()
	var metric dto.Metric
	if err := prometheus.RawUploadDoneProcessed.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}
