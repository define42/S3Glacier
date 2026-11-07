package shared

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestResponseDeadlineStartsWithFinalResponse(t *testing.T) {
	t.Parallel()
	w := &recordingDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	handler := withResponseWriteTimeout(http.HandlerFunc(func(response http.ResponseWriter, r *http.Request) {
		if len(w.deadlines) != 0 {
			t.Fatal("response deadline started before reading the upload")
		}
		response.WriteHeader(http.StatusContinue)
		if len(w.deadlines) != 0 {
			t.Fatal("informational response started the upload deadline")
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Fatal(err)
		}
		if len(w.deadlines) != 0 {
			t.Fatal("request-body buffering started the response deadline")
		}
		response.WriteHeader(http.StatusOK)
		if len(w.deadlines) != 1 || time.Until(w.deadlines[0]) <= 0 {
			t.Fatal("final response did not arm a future deadline")
		}
	}), time.Second)
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("slow upload")))
	if len(w.deadlines) != 1 || w.deadlines[0].IsZero() {
		t.Fatal("handler return cleared the deadline needed for the server's final flush")
	}
}

func TestResponseDeadlineRefreshesDuringLargeWrite(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	w := &recordingDeadlineWriter{
		ResponseRecorder: httptest.NewRecorder(), now: &now, writeDuration: 750 * time.Millisecond,
	}
	response := &deadlineResponseWriter{
		ResponseWriter: w, controller: http.NewResponseController(w),
		timeout: time.Second, now: func() time.Time { return now },
	}
	data := bytes.Repeat([]byte{'x'}, 4*responseWriteChunk)
	n, err := bytes.NewBuffer(data).WriteTo(response)
	if err != nil || n != int64(len(data)) || !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatalf("progressing response: bytes=%d err=%v", n, err)
	}
	if len(w.deadlines) != 4 || w.largestWrite > responseWriteChunk {
		t.Fatalf("large write bypassed deadline refresh: deadlines=%d largest=%d", len(w.deadlines), w.largestWrite)
	}
	if now.Sub(time.Unix(100, 0)) <= time.Second {
		t.Fatal("fixture did not exceed one response deadline window")
	}
}

func TestResponseDeadlineSetupFailureStopsWrites(t *testing.T) {
	t.Parallel()
	w := &recordingDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), deadlineErr: syscall.EIO}
	response := &deadlineResponseWriter{
		ResponseWriter: w, controller: http.NewResponseController(w), timeout: time.Second, now: time.Now,
	}
	for range 2 {
		if n, err := response.Write([]byte("must not write")); n != 0 || !errors.Is(err, syscall.EIO) {
			t.Fatalf("failed deadline: bytes=%d err=%v", n, err)
		}
	}
	if err := response.FlushError(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("flush after deadline failure: %v", err)
	}
	if len(w.deadlines) != 1 || w.Body.Len() != 0 || w.flushes != 0 {
		t.Fatal("deadline failure allowed an unbounded write or flush")
	}
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Fatalf("WriteHeader failure did not abort response: %v", got)
		}
	}()
	response.WriteHeader(http.StatusOK)
}

func TestResponseDeadlinePreservesControllerAndCustomWriters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		deadlineErr error
	}{
		{name: "supported"},
		{name: "custom writer", deadlineErr: fmt.Errorf("custom writer: %w", http.ErrNotSupported)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &recordingDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), deadlineErr: tc.deadlineErr}
			handler := withResponseWriteTimeout(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				unwrapper, ok := response.(interface{ Unwrap() http.ResponseWriter })
				if !ok || unwrapper.Unwrap() != w {
					t.Fatal("response controller cannot unwrap the deadline writer")
				}
				// An inner wrapper such as S3's response mapper need not expose
				// deadline methods: its writes still pass through the outer wrapper.
				inner := struct{ http.ResponseWriter }{response}
				if _, err := inner.Write([]byte("body")); err != nil {
					t.Fatal(err)
				}
				if err := http.NewResponseController(response).Flush(); err != nil {
					t.Fatal(err)
				}
			}), time.Second)
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Body.String() != "body" || w.flushes != 1 {
				t.Fatalf("response changed: body=%q flushes=%d", w.Body.String(), w.flushes)
			}
		})
	}
}

func TestResponseDeadlineCoversEmptyResponse(t *testing.T) {
	t.Parallel()
	w := &recordingDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	withResponseWriteTimeout(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), time.Second).
		ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/", nil))
	if len(w.deadlines) != 1 || w.deadlines[0].IsZero() {
		t.Fatal("empty response left the server's final header write unbounded")
	}
}

func TestResponseDeadlineUnsupportedFlushDoesNotPoisonWrites(t *testing.T) {
	t.Parallel()
	recorded := httptest.NewRecorder()
	plain := struct{ http.ResponseWriter }{recorded}
	handler := withResponseWriteTimeout(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(response).Flush(); !errors.Is(err, http.ErrNotSupported) {
			t.Fatalf("custom writer flush: %v", err)
		}
		response.(http.Flusher).Flush()
		if _, err := response.Write([]byte("still writable")); err != nil {
			t.Fatal(err)
		}
	}), time.Second)
	handler.ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorded.Body.String() != "still writable" {
		t.Fatal("unsupported flush prevented a later response write")
	}
}

type recordingDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines     []time.Time
	deadlineErr   error
	now           *time.Time
	writeDuration time.Duration
	largestWrite  int
	flushes       int
}

func (w *recordingDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return w.deadlineErr
}

func (w *recordingDeadlineWriter) Write(data []byte) (int, error) {
	if w.now != nil {
		if len(w.deadlines) == 0 || !w.now.Before(w.deadlines[len(w.deadlines)-1]) {
			return 0, os.ErrDeadlineExceeded
		}
		*w.now = w.now.Add(w.writeDuration)
	}
	w.largestWrite = max(w.largestWrite, len(data))
	return w.ResponseRecorder.Write(data)
}

func (w *recordingDeadlineWriter) FlushError() error {
	w.flushes++
	w.ResponseRecorder.Flush()
	return nil
}
