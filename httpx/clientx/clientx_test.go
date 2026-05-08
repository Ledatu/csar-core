package clientx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx/clientx"
)

type payload struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func newRequest(t *testing.T, ctx context.Context, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func TestDoJSON_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"alpha","n":42}`)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	got, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{Client: srv.Client()})
	if cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if got.Name != "alpha" || got.N != 42 {
		t.Fatalf("decoded = %+v", got)
	}
}

func TestDoJSONEmpty_NoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodDelete, srv.URL)
	if cerr := clientx.DoJSONEmpty(context.Background(), req, clientx.Options{Client: srv.Client()}); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
}

func TestDoJSON_ClientErrorCapturesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"bad input"}`)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodPost, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{Client: srv.Client()})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if cerr.Status != http.StatusBadRequest {
		t.Fatalf("status = %d", cerr.Status)
	}
	if !strings.Contains(string(cerr.Body), "bad input") {
		t.Fatalf("body = %q", cerr.Body)
	}
	if cerr.Method != http.MethodPost {
		t.Fatalf("method = %q", cerr.Method)
	}
	if !strings.Contains(cerr.Error(), "status 400") {
		t.Fatalf("error string = %q", cerr.Error())
	}
}

func TestDoJSON_ClientErrorBodyTruncatedTo4KiB(t *testing.T) {
	big := strings.Repeat("x", (4<<10)+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{Client: srv.Client()})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if len(cerr.Body) != 4<<10 {
		t.Fatalf("body len = %d, want %d", len(cerr.Body), 4<<10)
	}
}

func TestDoJSON_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{Client: srv.Client()})
	if cerr == nil || cerr.Status != http.StatusInternalServerError {
		t.Fatalf("expected 500 error, got %+v", cerr)
	}
}

func TestDoJSON_OversizeBody(t *testing.T) {
	body := strings.Repeat("y", 16<<10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client:           srv.Client(),
		MaxResponseBytes: 1024,
	})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(cerr, clientx.ErrResponseTooLarge) {
		t.Fatalf("errors.Is = false: %v", cerr)
	}
	if cerr.Body != nil {
		t.Fatalf("oversize body should be nil, got %d bytes", len(cerr.Body))
	}
}

func TestDoJSON_ContextCancelled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(release)
	}))
	defer srv.Close()
	defer func() { <-release }()

	ctx, cancel := context.WithCancel(context.Background())
	req := newRequest(t, ctx, http.MethodGet, srv.URL)

	done := make(chan *clientx.Error, 1)
	go func() {
		_, cerr := clientx.DoJSON[payload](ctx, req, clientx.Options{Client: srv.Client()})
		done <- cerr
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	cerr := <-done
	if cerr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(cerr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", cerr.Err)
	}
	if cerr.Status != 0 {
		t.Fatalf("status should be zero on transport error, got %d", cerr.Status)
	}
}

func TestDoJSON_TimeoutFromOptions(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		close(release)
	}))
	defer srv.Close()
	defer func() { <-release }()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client:  srv.Client(),
		Timeout: 40 * time.Millisecond,
	})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(cerr, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", cerr.Err)
	}
}

func TestDoJSON_InvalidJSONOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{Client: srv.Client()})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if cerr.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", cerr.Status)
	}
	if cerr.Err == nil || !strings.Contains(cerr.Err.Error(), "clientx: decode body") {
		t.Fatalf("expected decode body error, got %v", cerr.Err)
	}
	if len(cerr.Body) == 0 {
		t.Fatalf("expected body to be attached on decode error")
	}
}

func TestDoJSON_SuccessStatusesFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodPost, srv.URL)
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client:          srv.Client(),
		SuccessStatuses: []int{http.StatusOK},
	})
	if cerr == nil {
		t.Fatal("expected error, 201 not in allow list")
	}
	if cerr.Status != http.StatusCreated {
		t.Fatalf("status = %d", cerr.Status)
	}
}

type capturingHandler struct {
	mu      sync.Mutex
	records []map[string]any
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler. The Record parameter must be passed by
// value per the interface contract, so we cannot appease gocritic here.
//
//nolint:gocritic // hugeParam is unavoidable for slog.Handler
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, attrs)
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) attrMap(idx int) map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.records[idx]
}

func TestDoJSON_LogsRequestIDFromGatewayContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"upstream"}`)
	}))
	defer srv.Close()

	capture := &capturingHandler{}
	logger := slog.New(capture)

	id := gatewayctx.Identity{RequestID: "req-xyz-123"}
	ctx := gatewayctx.NewContext(context.Background(), &id)
	req := newRequest(t, ctx, http.MethodGet, srv.URL)

	_, cerr := clientx.DoJSON[payload](ctx, req, clientx.Options{
		Client: srv.Client(),
		Logger: logger,
	})
	if cerr == nil {
		t.Fatal("expected error")
	}

	if len(capture.records) != 1 {
		t.Fatalf("want 1 log record, got %d", len(capture.records))
	}
	attrs := capture.attrMap(0)
	if got, ok := attrs["request_id"].(string); !ok || got != "req-xyz-123" {
		t.Fatalf("request_id = %v", attrs["request_id"])
	}
	if got, ok := attrs["status"].(int64); !ok || got != int64(http.StatusBadGateway) {
		t.Fatalf("status attr = %v (%T)", attrs["status"], attrs["status"])
	}
	if got, ok := attrs["body_truncated"].(bool); !ok || got {
		t.Fatalf("body_truncated attr = %v", attrs["body_truncated"])
	}
}

func TestDoJSON_LogOmitsRequestIDWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	capture := &capturingHandler{}
	logger := slog.New(capture)

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	_, _ = clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client: srv.Client(),
		Logger: logger,
	})

	if len(capture.records) != 1 {
		t.Fatalf("want 1 log record, got %d", len(capture.records))
	}
	attrs := capture.attrMap(0)
	if _, ok := attrs["request_id"]; ok {
		t.Fatalf("request_id should be absent")
	}
}

func TestDoJSON_TransportError(t *testing.T) {
	req := newRequest(t, context.Background(), http.MethodGet, "http://127.0.0.1:1/nope")
	_, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client: &http.Client{Transport: &stubTransport{err: errors.New("boom")}},
	})
	if cerr == nil {
		t.Fatal("expected error")
	}
	if cerr.Status != 0 {
		t.Fatalf("status on transport error = %d, want 0", cerr.Status)
	}
	if cerr.Err == nil || !strings.Contains(cerr.Err.Error(), "clientx: request failed") {
		t.Fatalf("err = %v", cerr.Err)
	}
}

func TestDoJSON_RespectsExistingDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"name":"ok","n":1}`)
	}))
	defer srv.Close()

	parentCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()
	req := newRequest(t, parentCtx, http.MethodGet, srv.URL)

	_, cerr := clientx.DoJSON[payload](parentCtx, req, clientx.Options{
		Client:  srv.Client(),
		Timeout: time.Nanosecond,
	})
	if cerr != nil {
		t.Fatalf("existing deadline should not be overwritten: %v", cerr)
	}
}

type stubTransport struct {
	err error
}

func (s *stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, s.err
}

func TestError_Formatting(t *testing.T) {
	e := &clientx.Error{Status: 404, Method: http.MethodGet, Path: "/x", Err: errors.New("nope")}
	if got := e.Error(); got != "clientx: GET /x: status 404" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(e, e.Err) {
		t.Fatalf("errors.Is should find underlying error")
	}

	transport := &clientx.Error{Method: http.MethodPost, Path: "/y", Err: fmt.Errorf("clientx: request failed: %w", errors.New("dial fail"))}
	if got := transport.Error(); !strings.Contains(got, "clientx: request failed") {
		t.Fatalf("transport Error() = %q", got)
	}
}

func TestError_NilBehaviour(t *testing.T) {
	var e *clientx.Error
	if got := e.Error(); got == "" {
		t.Fatalf("nil *Error should format non-empty: %q", got)
	}
	if e.Unwrap() != nil {
		t.Fatalf("nil *Error Unwrap should be nil")
	}
}

// ensure the package does not accidentally eat enormous bodies when status is 2xx
func TestDoJSON_LargeButUnderLimitSucceeds(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"name":"`)
	buf.WriteString(strings.Repeat("a", 100_000))
	buf.WriteString(`","n":1}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	req := newRequest(t, context.Background(), http.MethodGet, srv.URL)
	got, cerr := clientx.DoJSON[payload](context.Background(), req, clientx.Options{
		Client:           srv.Client(),
		MaxResponseBytes: 1 << 20,
	})
	if cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if got.N != 1 || len(got.Name) != 100_000 {
		t.Fatalf("unexpected payload: n=%d name_len=%d", got.N, len(got.Name))
	}
}
