package stsclient

import (
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	routerRetryMaxRetries = 2
	routerRetryBaseDelay  = 100 * time.Millisecond
	routerRetryMaxDelay   = time.Second
	routerRetryBudgetCap  = 20
	routerRetryRefill     = time.Second
)

type retryTransport struct {
	base   http.RoundTripper
	logger *slog.Logger
	budget retryBudget
}

type retryBudget struct {
	mu     sync.Mutex
	tokens int
	last   time.Time
}

func newRetryTransport(base http.RoundTripper, logger *slog.Logger) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &retryTransport{
		base:   base,
		logger: logger,
		budget: retryBudget{
			tokens: routerRetryBudgetCap,
			last:   time.Now(),
		},
	}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !isRetryableRequest(req) {
		return t.base.RoundTrip(req)
	}

	var lastErr error
	for attempt := 0; attempt <= routerRetryMaxRetries; attempt++ {
		reqAttempt, err := cloneRequestForAttempt(req, attempt)
		if err != nil {
			return nil, err
		}

		resp, err := t.base.RoundTrip(reqAttempt)
		if !shouldRetryResponse(resp, err) {
			return resp, err
		}
		lastErr = err
		if attempt == routerRetryMaxRetries || !t.budget.take() {
			return resp, err
		}
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}

		delay := fullJitterDelay(attempt)
		t.logger.Warn("router request retrying", "method", req.Method, "path", req.URL.Path, "attempt", attempt+1, "delay", delay.String())
		if err := sleepContext(req.Context(), delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func isRetryableRequest(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return req.Header.Get("Idempotency-Key") != "" && (req.Body == nil || req.GetBody != nil)
	default:
		return false
	}
}

func cloneRequestForAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 0 {
		return req, nil
	}
	clone := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func shouldRetryResponse(resp *http.Response, err error) bool {
	if err != nil {
		return isRetryableNetworkError(err)
	}
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isRetryableNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "unexpected eof")
}

func fullJitterDelay(attempt int) time.Duration {
	maxDelay := routerRetryBaseDelay << attempt
	if maxDelay > routerRetryMaxDelay {
		maxDelay = routerRetryMaxDelay
	}
	return time.Duration(rand.Int64N(int64(maxDelay) + 1))
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (b *retryBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if elapsed := now.Sub(b.last); elapsed >= routerRetryRefill {
		refill := int(elapsed / routerRetryRefill)
		b.tokens = min(routerRetryBudgetCap, b.tokens+refill)
		b.last = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}
