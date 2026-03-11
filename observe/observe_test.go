package observe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInitTracer_Noop(t *testing.T) {
	tp, err := InitTracer(context.Background(), TraceConfig{
		ServiceName: "test-svc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected non-nil provider")
	}
	if err := tp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestNoop(t *testing.T) {
	tp := Noop()
	if tp == nil || tp.tp == nil {
		t.Fatal("expected non-nil noop provider")
	}
	tp.Close()
}

func TestShutdown_Nil(t *testing.T) {
	var tp *TracerProvider
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error on nil shutdown: %v", err)
	}
}

func TestNewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}
}

func TestMetricsHandler(t *testing.T) {
	reg := NewRegistry()
	h := MetricsHandler(reg)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") && !strings.Contains(ct, "openmetrics") {
		t.Errorf("unexpected Content-Type: %q", ct)
	}
}

func TestHTTPMiddleware(t *testing.T) {
	tp := Noop()
	defer tp.Close()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := HTTPMiddleware(tp.tp, "test-op")(inner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
