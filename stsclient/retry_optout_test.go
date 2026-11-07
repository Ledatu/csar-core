package stsclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type optoutRoundTripper func(*http.Request) (*http.Response, error)

func (f optoutRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWithoutRouterRetry(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		ctx := context.Background()
		if disabled {
			ctx = WithoutRouterRetry(ctx)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://router.invalid/create", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		transport := newRetryTransport(optoutRoundTripper(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
		}), nil)
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		want := 3
		if disabled {
			want = 1
		}
		if calls != want {
			t.Fatalf("disabled=%v calls=%d want=%d", disabled, calls, want)
		}
	}
}
