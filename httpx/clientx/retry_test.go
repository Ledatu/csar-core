package clientx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/httpx/retryafter"
)

func TestErrorPreservesOnlyBoundedRetryHints(t *testing.T) {
	for _, tc := range []struct {
		name, header, body string
		status             int
		want               time.Duration
	}{
		{"seconds", "3600", `{}`, 429, time.Hour},
		{"date", time.Now().UTC().Add(2 * time.Hour).Format(http.TimeFormat), `{}`, 429, 2 * time.Hour},
		{"bounded", "9999999999999999999999", `{}`, 429, retryafter.MaxDelay},
		{"credential plane", "", `{"code":"credential_throttled","status":502,"retry_after_ms":3600000}`, 502, time.Hour},
		{"CSAR", "", `{"code":"throttled","status":429,"retry_after_ms":3600000}`, 429, time.Hour},
		{"max of hints", "7200", `{"code":"throttled","status":429,"retry_after_ms":3600000}`, 429, 2 * time.Hour},
		{"envelope cap", "", `{"code":"throttled","status":429,"retry_after_ms":9223372036854775807}`, 429, retryafter.MaxDelay},
		{"negative", "-1", `{"code":"throttled","status":429,"retry_after_ms":-1}`, 429, 0},
		{"wrong status", "", `{"code":"throttled","status":503,"retry_after_ms":3600000}`, 429, 0},
		{"unmarked provider envelope", "", `{"retry_after_ms":3600000}`, 429, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", tc.header)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
			_, err := DoJSON[any](req.Context(), req, Options{Client: srv.Client()})
			if err == nil {
				t.Fatal("expected failure")
			}
			if tc.name == "date" {
				if err.RetryAfter < tc.want-5*time.Second || err.RetryAfter > tc.want {
					t.Fatalf("date hint %s", err.RetryAfter)
				}
			} else if err.RetryAfter != tc.want {
				t.Fatalf("got %s want %s", err.RetryAfter, tc.want)
			}
		})
	}
}
