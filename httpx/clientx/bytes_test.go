package clientx

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDoBytesPreservesBinaryWithoutJSONDecoding(t *testing.T) {
	want := []byte{'P', 'K', 3, 4, 0, 255, 128}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		_, _ = w.Write(want)
	}))
	defer server.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, failure := DoBytes(req.Context(), req, Options{Client: server.Client(), MaxResponseBytes: int64(len(want))})
	if failure != nil || !bytes.Equal(got, want) || calls.Load() != 1 {
		t.Fatalf("binary response = %v, error = %v, attempts = %d", got, failure, calls.Load())
	}
}

func TestDoBytesFailureNeverReturnsBodyOrRetries(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		body      string
		limit     int64
		oversized bool
	}{
		{name: "oversized successful document", status: http.StatusOK, body: "PK12345", limit: 4, oversized: true},
		{name: "gateway error", status: http.StatusServiceUnavailable, body: `{"error":"unavailable"}`, limit: 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, failure := DoBytes(req.Context(), req, Options{Client: server.Client(), MaxResponseBytes: test.limit})
			if body != nil || failure == nil || failure.Status != test.status || calls.Load() != 1 {
				t.Fatalf("failed response body = %v, error = %v, attempts = %d", body, failure, calls.Load())
			}
			if test.oversized && !errors.Is(failure, ErrResponseTooLarge) {
				t.Fatalf("missing overflow cause: %v", failure)
			}
		})
	}
}
