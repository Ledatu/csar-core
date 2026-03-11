// Package httpmiddleware provides composable HTTP middleware for
// request ID propagation, structured access logging, panic recovery,
// request timeouts, and body size limits.
package httpmiddleware

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

const headerRequestID = "X-Request-ID"

// Middleware is a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares so the first in the list is the outermost wrapper.
//
//	Chain(A, B, C)(handler) == A(B(C(handler)))
func Chain(mws ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			next = mws[i](next)
		}
		return next
	}
}

// RequestID ensures every request has an X-Request-ID header.
// If the inbound request already carries one (e.g. from the gateway),
// it is preserved; otherwise a new random ID is generated.
// The ID is also set on the response headers.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(headerRequestID)
		if id == "" {
			id = generateID()
			r.Header.Set(headerRequestID, id)
		}
		w.Header().Set(headerRequestID, id)
		next.ServeHTTP(w, r)
	})
}

// AccessLog returns middleware that logs each request at Info level
// with method, path, status, and duration.
func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := wrapRecorder(w)
			next.ServeHTTP(rec, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.statusCode,
				"duration", time.Since(start).String(),
				"request_id", r.Header.Get(headerRequestID),
			)
		})
	}
}

// Recover returns middleware that catches panics, logs them, and
// responds with 500 Internal Server Error.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					logger.Error("panic recovered",
						"panic", v,
						"stack", string(debug.Stack()),
						"method", r.Method,
						"path", r.URL.Path,
						"request_id", r.Header.Get(headerRequestID),
					)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout returns middleware that enforces a hard per-request deadline.
// The handler is run in a separate goroutine; if it does not complete
// within d the client receives 503 Service Unavailable. The response
// body is buffered until the handler finishes or the deadline fires,
// which means this middleware is not suitable for streaming responses.
// For streaming handlers, apply the deadline to the context directly
// and check ctx.Done() cooperatively instead.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, http.StatusText(http.StatusServiceUnavailable))
	}
}

// MaxBodySize returns middleware that limits the request body to n bytes.
// If the body exceeds the limit, the reader returns an error.
func MaxBodySize(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// wrapRecorder returns a responseRecorder that preserves the optional
// interfaces (http.Flusher, http.Hijacker, io.ReaderFrom) supported by
// the underlying ResponseWriter. Without this, enabling access logging
// would silently break SSE, websockets, and optimized copy paths.
func wrapRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
}

// responseRecorder wraps http.ResponseWriter to capture the status code
// while delegating all other calls — including optional interfaces —
// to the underlying writer via Unwrap.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.written {
		r.statusCode = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter. The net/http package
// uses this to discover optional interfaces (Flusher, Hijacker, etc.)
// on the wrapped writer via [http.ResponseController].
func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush delegates to the underlying writer's Flush if supported.
// This keeps SSE / streaming responses working through the recorder.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
