package csarclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/httpx/clientx"
)

func newTestClient(t *testing.T, server *httptest.Server, customize func(*Config)) *Client {
	t.Helper()
	cfg := Config{BaseURL: server.URL, HTTPClient: server.Client()}
	if customize != nil {
		customize(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWorkerPreservesProtocolAndDoesNotReplay(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Idempotency-Key") != "caller-key" {
			t.Error("caller header changed")
		}
		w.Header().Set("X-CSAR-Status", "backpressure")
		w.Header().Set("X-CSAR-Wait-MS", "1234")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"code":"throttled","status":503,"retry_after_ms":9999}`))
	}))
	defer s.Close()
	_, err := DoJSON[any](context.Background(), newTestClient(t, s, nil), Request{Method: "POST", Path: "/source", Body: map[string]int{"limit": 100}, Headers: http.Header{"Idempotency-Key": []string{"caller-key"}}, ReplaySafe: true})
	if err == nil || err.CSARStatus != "backpressure" || err.RetryAfter != 1234*time.Millisecond || calls.Load() != 1 {
		t.Fatalf("worker result calls=%d err=%+v", calls.Load(), err)
	}
}

func TestRetryAfterHeaderPrecedesBodyHint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-CSAR-Status", "throttled")
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"code":"throttled","status":503,"retry_after_ms":9000}`))
	}))
	defer s.Close()
	_, err := DoJSON[any](context.Background(), newTestClient(t, s, nil), Request{Method: "GET", Path: "/x"})
	if err == nil || err.RetryAfter != 2*time.Second {
		t.Fatal("body overrode protocol header", err)
	}
}

func TestGenericClientRejectsAuthorityTraversalAndReservedHeaders(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	defer s.Close()
	c := newTestClient(t, s, nil)
	for _, path := range []string{"https://other.invalid/x", "//other.invalid/x", "/a/../x", "/a/%2e%2e/x", "/a%2fb", "/a\\b", "/x#secret"} {
		_, err := DoJSON[any](context.Background(), c, Request{Method: "GET", Path: path})
		if err == nil || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe route accepted %q", path)
		}
	}
	for _, header := range []string{"X-Csar-Authorization", "X-Gateway-Subject", "Host"} {
		_, err := DoJSON[any](context.Background(), c, Request{Method: "GET", Path: "/x", Headers: http.Header{header: []string{"spoof"}}})
		if err == nil {
			t.Fatal("reserved header accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached network")
	}
}

func TestGenericClientDoesNotFollowRedirect(t *testing.T) {
	var escaped atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { escaped.Add(1); _, _ = w.Write([]byte(`{}`)) }))
	defer other.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	_, err := DoJSON[any](context.Background(), newTestClient(t, s, nil), Request{Method: "POST", Path: "/x", Body: map[string]string{"id": "1"}})
	if err == nil || err.Status != 307 || escaped.Load() != 0 {
		t.Fatal("redirect escaped configured router")
	}
}

func TestShortWaitRequiresExplicitReplayAndKnownRouterSignal(t *testing.T) {
	for _, status := range []string{"backpressure", "circuit_open", "throttle_unavailable", ""} {
		for _, safe := range []bool{false, true} {
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) > 1 {
					_, _ = w.Write([]byte(`{"ok":true}`))
					return
				}
				w.Header().Set("X-CSAR-Status", status)
				w.Header().Set("X-CSAR-Wait-MS", "1")
				w.WriteHeader(503)
			}))
			c := newTestClient(t, s, func(cfg *Config) { cfg.WaitBudget = time.Second; cfg.MaxRetries = 1 })
			_, err := DoJSON[any](context.Background(), c, Request{Method: "POST", Path: "/x", Body: struct{}{}, ReplaySafe: safe})
			s.Close()
			wantRetry := safe && status == "backpressure"
			if wantRetry && (err != nil || calls.Load() != 2) {
				t.Fatal("safe bounded retry failed")
			}
			if !wantRetry && (err == nil || calls.Load() != 1) {
				t.Fatal("unsafe/unknown response retried")
			}
		}
	}
}

func TestGenericClientBoundsAndCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"payload":"oversize"}`)) }))
	defer s.Close()
	c := newTestClient(t, s, func(cfg *Config) { cfg.MaxRequestBytes = 4; cfg.MaxResponseBytes = 4 })
	_, err := DoJSON[any](context.Background(), c, Request{Method: "POST", Path: "/x", Body: map[string]string{"x": "large"}})
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatal(err)
	}
	_, err = DoJSON[any](context.Background(), c, Request{Method: "GET", Path: "/x"})
	if !errors.Is(err, clientx.ErrResponseTooLarge) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = DoJSON[any](ctx, c, Request{Method: "GET", Path: "/x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation not preserved", err)
	}
}
