// Package csarclient is a marketplace-neutral, bounded Go client for CSAR routes.
// Supply the existing stsclient.RouterClient's HTTP client for authenticated calls.
package csarclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ledatu/csar-core/httpx/clientx"
	"github.com/ledatu/csar-core/stsclient"
)

var ErrInvalidRequest = errors.New("csarclient: invalid request")
var ErrRequestTooLarge = errors.New("csarclient: request exceeds size limit")

type Config struct {
	BaseURL                           string
	HTTPClient                        *http.Client
	Timeout                           time.Duration
	MaxRequestBytes, MaxResponseBytes int64
	Logger                            *slog.Logger
	// WaitBudget and MaxRetries opt into short synchronous backpressure waits.
	// Their zero values keep worker mode single-attempt, returning retry hints.
	WaitBudget time.Duration
	MaxRetries int
}

type Client struct {
	base *url.URL
	http *http.Client
	cfg  Config
}
type Request struct {
	Method, Path string
	Body         any
	Headers      http.Header
	// ReplaySafe is explicit domain evidence, not inferred from POST or a header.
	// Worker mode still performs one attempt even when true.
	ReplaySafe bool
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || cfg.HTTPClient == nil || cfg.Timeout < 0 || cfg.MaxRequestBytes < 0 || cfg.MaxResponseBytes < 0 || cfg.WaitBudget < 0 || cfg.WaitBudget > 5*time.Second || cfg.MaxRetries < 0 || cfg.MaxRetries > 3 {
		return nil, fmt.Errorf("csarclient: invalid configuration")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 1 << 20
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.MaxRequestBytes > 64<<20 || cfg.MaxResponseBytes > 64<<20 || !safePath(u) {
		return nil, fmt.Errorf("csarclient: invalid bounds or base path")
	}
	clone := *cfg.HTTPClient
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: u, http: &clone, cfg: cfg}, nil
}

func safePath(u *url.URL) bool {
	if u.Path == "" {
		return true
	}
	lower := strings.ToLower(u.EscapedPath())
	clean := strings.TrimSuffix(u.Path, "/")
	if u.Path == "/" {
		clean = "/"
	}
	return strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") && !strings.ContainsAny(u.Path, "\\\x00\r\n") && path.Clean(u.Path) == clean && !strings.Contains(lower, "%2f") && !strings.Contains(lower, "%5c")
}

func (c *Client) build(ctx context.Context, r Request, payload []byte) (*http.Request, error) {
	rel, err := url.ParseRequestURI(r.Path)
	if err != nil || strings.Contains(r.Path, "#") || rel.IsAbs() || rel.Host != "" || rel.User != nil || rel.Fragment != "" || !safePath(rel) || rel.Path == "" {
		return nil, ErrInvalidRequest
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return nil, ErrInvalidRequest
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + rel.Path
	u.RawPath = ""
	u.RawQuery = rel.RawQuery
	req, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for name, values := range r.Headers {
		lower := strings.ToLower(name)
		if lower == "host" || lower == "x-csar-authorization" || strings.HasPrefix(lower, "x-gateway-") {
			return nil, ErrInvalidRequest
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !r.ReplaySafe {
		// A caller-supplied idempotency header can make net/http retry a
		// reused connection. Only the reviewed replay policy may permit body
		// recreation; disabling SDK/STS retry loops alone is insufficient.
		req.GetBody = nil
	}
	return req, nil
}

// DoJSON uses existing STS/clientx primitives; it never holds marketplace credentials.
func DoJSON[T any](ctx context.Context, c *Client, r Request) (T, *clientx.Error) {
	var zero T
	if c == nil {
		return zero, &clientx.Error{Origin: "client_request", Err: ErrInvalidRequest}
	}
	ctx, cancel := context.WithTimeout(stsclient.WithoutRouterRetry(ctx), c.cfg.Timeout)
	defer cancel()
	var payload []byte
	if r.Body != nil {
		var err error
		payload, err = json.Marshal(r.Body)
		if err != nil {
			return zero, &clientx.Error{Origin: "client_request", Err: ErrInvalidRequest}
		}
	}
	if int64(len(payload)) > c.cfg.MaxRequestBytes {
		return zero, &clientx.Error{Origin: "client_request", Err: ErrRequestTooLarge}
	}
	started := time.Now()
	for attempt := 0; ; attempt++ {
		req, err := c.build(ctx, r, payload)
		if err != nil {
			return zero, &clientx.Error{Origin: "client_request", Err: err}
		}
		out, callErr := clientx.DoJSON[T](ctx, req, clientx.Options{Client: c.http, MaxResponseBytes: c.cfg.MaxResponseBytes, Logger: c.cfg.Logger})
		if callErr == nil {
			return out, nil
		}
		if callErr.CSARWait > 0 {
			callErr.RetryAfter = callErr.CSARWait
		} else if callErr.RetryAfterHeader > 0 {
			callErr.RetryAfter = callErr.RetryAfterHeader
		}
		if !r.ReplaySafe || c.cfg.WaitBudget == 0 || attempt >= c.cfg.MaxRetries || callErr.Status != 503 || (callErr.CSARStatus != "throttled" && callErr.CSARStatus != "backpressure") {
			return zero, callErr
		}
		delay := callErr.RetryAfter
		if delay <= 0 {
			delay = time.Second
		}
		if time.Since(started)+delay > c.cfg.WaitBudget {
			return zero, callErr
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, &clientx.Error{Origin: "client_cancelled", Err: ctx.Err()}
		case <-timer.C:
		}
	}
}
