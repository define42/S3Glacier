//go:build integration

package shared

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"glacier/archive"
	"glacier/bucket"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func TestResponseDeadlineReleasesArchiveLock(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{
		{name: "HTTP1"},
		{name: "HTTP2", h2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bucket.Bucket{Name: "logs", Path: filepath.Join(t.TempDir(), "logs"), TarFilesPerHour: 1}
			const id = "20261107-1200-4000-8000-000000000001"
			path, _, err := GetBucketContainerFile(b, id)
			if err != nil {
				t.Fatal(err)
			}
			// Exceed both a TCP send buffer and HTTP/2's unread-stream window.
			data := bytes.Repeat([]byte{'x'}, 8<<20)
			header := &tar.Header{Name: id, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(data))}
			if _, err := archive.Default.Append(t.Context(), path, header, data, sha256.Sum256(data)); err != nil {
				t.Fatal(err)
			}
			started, finished := make(chan struct{}), make(chan struct{})
			writeError := make(chan error, 1)
			handler := withResponseWriteTimeout(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(finished)
				observed := &deadlineWriteObserver{ResponseWriter: w, started: started, failed: writeError}
				GetBucketFile(observed, mux.SetURLVars(r, map[string]string{"id": id}), b)
			}), 500*time.Millisecond)
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = tc.h2
			if tc.h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 5 * time.Second
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { response.Body.Close() })
			if response.StatusCode != http.StatusOK || (response.ProtoMajor == 2) != tc.h2 {
				t.Fatalf("unexpected response: %s %s", response.Proto, response.Status)
			}
			// Intentionally leave the response body unread. The client remains
			// connected; only the server's write deadline releases the reader.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			awaitDeadlineSignal(t, ctx, started, "response write")
			queued := &deadlineQueuedContext{Context: ctx, queued: make(chan struct{})}
			appended := make(chan error, 1)
			appendDone := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-appendDone:
				case <-time.After(5 * time.Second):
					t.Error("append worker did not stop during cleanup")
				}
			})
			go func() {
				defer close(appendDone)
				payload := []byte("after stalled download")
				header := &tar.Header{Name: "next-entry", Typeflag: tar.TypeReg, Size: int64(len(payload))}
				_, err := archive.Default.Append(queued, path, header, payload, sha256.Sum256(payload))
				appended <- err
			}()
			awaitDeadlineSignal(t, ctx, queued.queued, "append waiting for the download lock")
			select {
			case err := <-writeError:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("stalled write failed without a deadline error: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("stalled response did not hit its write deadline")
			}
			awaitDeadlineSignal(t, ctx, finished, "download handler releasing its reader")
			select {
			case err := <-appended:
				if err != nil {
					t.Fatalf("append after stalled download: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("timed-out download retained the archive lock")
			}
		})
	}
}

type deadlineWriteObserver struct {
	http.ResponseWriter
	started chan struct{}
	failed  chan error
	once    sync.Once
}

func (w *deadlineWriteObserver) Write(data []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	n, err := w.ResponseWriter.Write(data)
	if err != nil {
		select {
		case w.failed <- err:
		default:
		}
	}
	return n, err
}

type deadlineQueuedContext struct {
	context.Context
	queued chan struct{}
	once   sync.Once
}

func (c *deadlineQueuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.queued) })
	return c.Context.Done()
}

func awaitDeadlineSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s", description)
	}
}
