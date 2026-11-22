package csarclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNonReplaySafeBodyCannotBeRecreatedByTransport(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if writes.Add(1) == 1 {
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client := newTestClient(t, server, nil)
	if _, e := DoJSON[any](context.Background(), client, Request{Method: "GET", Path: "/warm", ReplaySafe: true}); e != nil {
		t.Fatal(e)
	}
	_, e := DoJSON[any](context.Background(), client, Request{Method: "PUT", Path: "/write", Body: map[string]int{"bid": 5000000}, Headers: http.Header{"Idempotency-Key": []string{"caller-header-does-not-grant-replay"}}})
	if e == nil || writes.Load() != 1 {
		t.Fatal("unsafe transport replay", writes.Load(), e)
	}
}
func TestExplicitReplayPolicyOwnsGetBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	client := newTestClient(t, server, nil)
	for _, safe := range []bool{false, true} {
		req, e := client.build(context.Background(), Request{Method: "POST", Path: "/source", Body: struct{}{}, ReplaySafe: safe}, []byte(`{}`))
		if e != nil || (req.GetBody != nil) != safe {
			t.Fatal("replay policy ignored", safe, e)
		}
	}
}

func TestHTTP429WaitRequiresBothReplaySafetyAndExplicitOptIn(t *testing.T) {
	for _, test := range []struct {
		safe, opt bool
		want      int
	}{{false, true, 1}, {true, false, 1}, {true, true, 2}} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("X-CSAR-Wait-MS", "2")
				w.WriteHeader(429)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		}))
		client := newTestClient(t, server, func(c *Config) { c.WaitBudget = 50 * time.Millisecond; c.MaxRetries = 1; c.RetryHTTP429 = test.opt })
		_, e := DoJSON[any](context.Background(), client, Request{Method: "POST", Path: "/read", Body: struct{}{}, ReplaySafe: test.safe})
		server.Close()
		if calls != test.want || (e == nil) != (test.want == 2) {
			t.Fatal(test, calls, e)
		}
	}
}
