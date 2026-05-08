// Package clientx issues outbound HTTP-JSON requests with uniform error
// capture, size limits, context-aware timeouts, and structured logging of
// non-success responses. Callers always supply their own *http.Client;
// this package never owns a shared client singleton.
package clientx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
)

// ErrResponseTooLarge is returned when the server response exceeds
// Options.MaxResponseBytes. The oversize body is discarded and never
// attached to the returned Error or log record.
var ErrResponseTooLarge = errors.New("clientx: response exceeds MaxResponseBytes")

const (
	defaultMaxResponseBytes int64 = 1 << 20 // 1 MiB
	logBodyCap              int   = 4 << 10 // 4 KiB
)

// Options configures a DoJSON / DoJSONEmpty invocation. The Client field is
// mandatory in production (nil falls back to http.DefaultClient only to keep
// tests terse). MaxResponseBytes <= 0 defaults to 1 MiB. SuccessStatuses may
// be empty to accept any 2xx response.
type Options struct {
	Client           *http.Client
	Timeout          time.Duration
	MaxResponseBytes int64
	Logger           *slog.Logger
	SuccessStatuses  []int
}

// Error is returned by DoJSON and DoJSONEmpty for every failure mode. Status
// is zero on transport / context errors. Body holds up to 4 KiB of the
// captured response body and is always nil when Err is ErrResponseTooLarge.
type Error struct {
	Status int
	Path   string
	Method string
	Body   []byte
	Err    error
}

// Error implements the error interface. When Status is non-zero callers see
// a stable, log-friendly summary; otherwise the wrapped Err message is used.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Status != 0 {
		return fmt.Sprintf("clientx: %s %s: status %d", e.Method, e.Path, e.Status)
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "clientx: error"
}

// Unwrap exposes the underlying cause so callers can use errors.Is and
// errors.As (for example errors.Is(err, ErrResponseTooLarge) or
// errors.Is(err, context.DeadlineExceeded)).
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// DoJSON issues req, requires a successful status, and decodes the response
// body into T. On any failure (transport, oversize, non-success status,
// decode error) a non-nil *Error is returned and T is its zero value.
func DoJSON[T any](ctx context.Context, req *http.Request, opts Options) (T, *Error) {
	var zero T
	raw, status, cerr := exec(ctx, req, opts)
	if cerr != nil {
		return zero, cerr
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		capped, _ := capBody(raw)
		return zero, &Error{
			Status: status,
			Method: req.Method,
			Path:   req.URL.Path,
			Body:   capped,
			Err:    fmt.Errorf("clientx: decode body: %w", err),
		}
	}
	return out, nil
}

// DoJSONEmpty issues req and requires a successful status, discarding the
// response body. It is intended for 204 No Content and similar endpoints.
func DoJSONEmpty(ctx context.Context, req *http.Request, opts Options) *Error {
	_, _, cerr := exec(ctx, req, opts)
	return cerr
}

func exec(ctx context.Context, req *http.Request, opts Options) ([]byte, int, *Error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}

	if opts.Timeout > 0 {
		if _, has := req.Context().Deadline(); !has {
			tctx, cancel := context.WithTimeout(ctx, opts.Timeout)
			defer cancel()
			req = req.WithContext(tctx)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, &Error{
			Method: req.Method,
			Path:   req.URL.Path,
			Err:    fmt.Errorf("clientx: request failed: %w", err),
		}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if readErr != nil {
		return nil, resp.StatusCode, &Error{
			Status: resp.StatusCode,
			Method: req.Method,
			Path:   req.URL.Path,
			Err:    fmt.Errorf("clientx: read body: %w", readErr),
		}
	}

	if int64(len(raw)) > maxBytes {
		logOversize(ctx, opts, req, resp.StatusCode)
		return nil, resp.StatusCode, &Error{
			Status: resp.StatusCode,
			Method: req.Method,
			Path:   req.URL.Path,
			Body:   nil,
			Err:    ErrResponseTooLarge,
		}
	}

	if !isSuccess(resp.StatusCode, opts.SuccessStatuses) {
		capped, truncated := capBody(raw)
		logNonSuccess(ctx, opts, req, resp.StatusCode, truncated)
		return nil, resp.StatusCode, &Error{
			Status: resp.StatusCode,
			Method: req.Method,
			Path:   req.URL.Path,
			Body:   capped,
		}
	}

	return raw, resp.StatusCode, nil
}

func isSuccess(status int, allow []int) bool {
	if len(allow) == 0 {
		return status >= 200 && status < 300
	}
	for _, s := range allow {
		if s == status {
			return true
		}
	}
	return false
}

func capBody(raw []byte) ([]byte, bool) {
	if len(raw) <= logBodyCap {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out, false
	}
	out := make([]byte, logBodyCap)
	copy(out, raw[:logBodyCap])
	return out, true
}

func logNonSuccess(ctx context.Context, opts Options, req *http.Request, status int, truncated bool) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []any{
		slog.Int("status", status),
		slog.String("method", req.Method),
		slog.String("path", req.URL.Path),
		slog.Bool("body_truncated", truncated),
	}
	if id, ok := gatewayctx.FromContext(ctx); ok && id.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", id.RequestID))
	}
	logger.WarnContext(ctx, "clientx: non-success response", attrs...)
}

func logOversize(ctx context.Context, opts Options, req *http.Request, status int) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []any{
		slog.Int("status", status),
		slog.String("method", req.Method),
		slog.String("path", req.URL.Path),
		slog.String("err", ErrResponseTooLarge.Error()),
	}
	if id, ok := gatewayctx.FromContext(ctx); ok && id.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", id.RequestID))
	}
	logger.WarnContext(ctx, "clientx: response too large", attrs...)
}
