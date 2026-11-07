package shared

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const responseWriteTimeout = 30 * time.Second
const responseWriteChunk = 32 << 10

// LimitResponseWrites bounds stalled response writes to 30 seconds. The deadline
// starts with the final response and is refreshed between body chunks and flushes,
// so request-body buffering and the total duration of a progressing download are
// not limited. HTTP/1 and HTTP/2 servers support these deadlines; custom writers
// that return http.ErrNotSupported retain their existing behavior.
func LimitResponseWrites(next http.Handler) http.Handler {
	return withResponseWriteTimeout(next, responseWriteTimeout)
}

func withResponseWriteTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := &deadlineResponseWriter{
			ResponseWriter: w, controller: http.NewResponseController(w),
			timeout: timeout, now: time.Now,
		}
		next.ServeHTTP(response, r)
		if !response.started {
			// The server still has to write headers for an empty response.
			if err := response.refresh(); err != nil {
				panic(http.ErrAbortHandler)
			}
		}
		// Leave the last deadline armed for net/http's final buffered flush.
		// The HTTP/1 server clears it before accepting the next request.
	})
}

type deadlineResponseWriter struct {
	http.ResponseWriter
	controller  *http.ResponseController
	timeout     time.Duration
	now         func() time.Time
	err         error
	started     bool
	unsupported bool
}

func (w *deadlineResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *deadlineResponseWriter) refresh() error {
	if w.err != nil {
		return w.err
	}
	w.started = true
	if w.unsupported {
		return nil
	}
	err := w.controller.SetWriteDeadline(w.now().Add(w.timeout))
	if errors.Is(err, http.ErrNotSupported) {
		w.unsupported = true
		return nil
	}
	if err != nil {
		w.err = fmt.Errorf("set response write deadline: %w", err)
	}
	return w.err
}

func (w *deadlineResponseWriter) WriteHeader(status int) {
	// An informational response may precede a slowly buffered upload body.
	if status < http.StatusOK {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if err := w.refresh(); err != nil {
		// WriteHeader cannot return an error. Abort the response rather than
		// performing an unbounded write after deadline setup has failed.
		panic(http.ErrAbortHandler)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	written := 0
	for {
		if err := w.refresh(); err != nil {
			return written, err
		}
		chunk := data[:min(len(data), responseWriteChunk)]
		n, err := w.ResponseWriter.Write(chunk)
		written += n
		if err == nil && n != len(chunk) {
			err = io.ErrShortWrite
		}
		if err != nil {
			w.err = err
			return written, err
		}
		data = data[n:]
		if len(data) == 0 {
			return written, nil
		}
	}
}

func (w *deadlineResponseWriter) FlushError() error {
	if err := w.refresh(); err != nil {
		return err
	}
	err := w.controller.Flush()
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		w.err = err
	}
	return err
}

func (w *deadlineResponseWriter) Flush() {
	if err := w.FlushError(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		w.err = err
	}
}
