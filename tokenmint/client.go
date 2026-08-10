package tokenmint

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ledatu/csar-core/httpx/clientx"
)

// Error classes returned by a grant. Callers map these onto their own
// transport's status codes and onto retry policy.
var (
	// ErrInvalidClient means the upstream rejected the credential pair.
	// Retrying cannot help until the credential itself is replaced.
	ErrInvalidClient = errors.New("tokenmint: upstream rejected the client credentials")

	// ErrUpstream is a transient upstream failure: 5xx, 429, timeout, dial.
	ErrUpstream = errors.New("tokenmint: upstream token endpoint failed")

	// ErrMalformedResponse means the upstream answered 2xx with something we
	// cannot interpret as a token.
	ErrMalformedResponse = errors.New("tokenmint: malformed token response")

	// ErrHostNotAllowed means a profile's host is not in the allowlist. It
	// should be impossible after config validation; it exists because the
	// check is repeated at request time.
	ErrHostNotAllowed = errors.New("tokenmint: token endpoint host is not allowed")
)

// grantResponse is the normalized result of one successful token request.
type grantResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   time.Duration
}

// upstreamError carries the retry hint from a failed request.
type upstreamError struct {
	status     int
	retryAfter time.Duration
	msg        string
}

func (e *upstreamError) Error() string {
	return fmt.Sprintf("tokenmint: token endpoint returned %d: %s", e.status, e.msg)
}

func (e *upstreamError) Unwrap() error { return ErrUpstream }

// newHTTPClient builds the outbound client used for every grant.
//
// The hardening here is not incidental. This client carries a long-lived
// client_secret to a third party, so each setting closes a specific path by
// which that secret could reach somewhere it should not:
//
//   - Proxy is nil so a HTTP_PROXY value in the container environment cannot
//     silently interpose.
//   - Redirects are a hard error, not ErrUseLastResponse: following a 302
//     would replay the credential to whatever host the upstream named.
//   - The dial guard rejects internal addresses even for an allowlisted
//     hostname, which is what makes DNS rebinding ineffective. It runs on every
//     dial rather than once at startup.
func newHTTPClient(cfg *Config, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("tokenmint: invalid address %q: %w", addr, err)
		}
		if cfg.AllowPrivate {
			return dialer.DialContext(ctx, network, addr)
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("tokenmint: resolve %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("tokenmint: no addresses for %q", host)
		}
		for _, ipAddr := range ips {
			if err := clientx.CheckInternalIP(ipAddr.IP, clientx.AllInternalIPClasses()); err != nil {
				return nil, fmt.Errorf("tokenmint: refusing to dial %q: %w", host, err)
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}

	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("tokenmint: refusing to follow a redirect from a token endpoint")
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dial,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

// doGrant executes one client_credentials request.
func doGrant(ctx context.Context, client *http.Client, cfg *Config, p *Profile, clientID, clientSecret string) (grantResponse, error) {
	u, err := url.Parse(p.TokenURL)
	if err != nil {
		return grantResponse{}, fmt.Errorf("tokenmint: parse token_url: %w", err)
	}
	// Re-check at request time, not only at config load: this is the last
	// point before a credential leaves the process.
	if !cfg.HostAllowed(u.Hostname()) {
		return grantResponse{}, fmt.Errorf("%w: %s", ErrHostNotAllowed, u.Hostname())
	}

	req, err := buildGrantRequest(ctx, p, clientID, clientSecret)
	if err != nil {
		return grantResponse{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Never wrap the raw error into a message that could echo the body.
		return grantResponse{}, fmt.Errorf("%w: %v", ErrUpstream, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, p.MaxResponseBytes+1))
	if err != nil {
		return grantResponse{}, fmt.Errorf("%w: read body: %v", ErrUpstream, err)
	}
	if int64(len(body)) > p.MaxResponseBytes {
		return grantResponse{}, fmt.Errorf("%w: response exceeds max_response_bytes (%d)", ErrMalformedResponse, p.MaxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return grantResponse{}, classifyFailure(resp, body)
	}

	return parseGrantResponse(p, body)
}

func buildGrantRequest(ctx context.Context, p *Profile, clientID, clientSecret string) (*http.Request, error) {
	params := make(map[string]string, len(p.StaticParams)+2)
	for k, v := range p.StaticParams {
		params[k] = v
	}
	params[p.ClientIDParam] = clientID
	params[p.ClientSecretParam] = clientSecret

	var (
		body        io.Reader
		contentType string
	)

	switch p.BodyStyle {
	case BodyStyleForm:
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"

	case BodyStyleJSON:
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("tokenmint: encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
		contentType = "application/json"

	default:
		return nil, fmt.Errorf("tokenmint: unsupported body_style %q", p.BodyStyle)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, body)
	if err != nil {
		return nil, fmt.Errorf("tokenmint: build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// classifyFailure decides whether a non-2xx response is worth retrying soon.
func classifyFailure(resp *http.Response, body []byte) error {
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))

	// The body of a failed token request routinely echoes the submitted
	// parameters, so it is summarized to an error code and never carried
	// verbatim into an error or a log line.
	code := extractErrorCode(body)

	switch {
	case resp.StatusCode == http.StatusUnauthorized,
		resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusBadRequest && isCredentialErrorCode(code):
		return fmt.Errorf("%w (status %d, code %q)", ErrInvalidClient, resp.StatusCode, code)
	default:
		return &upstreamError{
			status:     resp.StatusCode,
			retryAfter: retryAfter,
			msg:        fmt.Sprintf("code %q", code),
		}
	}
}

func isCredentialErrorCode(code string) bool {
	switch strings.ToLower(code) {
	case "invalid_client", "unauthorized_client", "invalid_grant", "access_denied":
		return true
	default:
		return false
	}
}

// extractErrorCode pulls the RFC 6749 "error" field when present. Anything
// else collapses to a placeholder rather than leaking body content.
func extractErrorCode(body []byte) string {
	var probe struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && probe.Error != "" {
		if len(probe.Error) > 64 {
			return probe.Error[:64]
		}
		return probe.Error
	}
	return "unspecified"
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func parseGrantResponse(p *Profile, body []byte) (grantResponse, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return grantResponse{}, fmt.Errorf("%w: not JSON", ErrMalformedResponse)
	}

	token, _ := lookupString(doc, p.AccessTokenPath)
	if token == "" {
		return grantResponse{}, fmt.Errorf("%w: %q missing or empty", ErrMalformedResponse, p.AccessTokenPath)
	}

	tokenType, _ := lookupString(doc, p.TokenTypePath)
	if p.ExpectedTokenType != "" && tokenType != "" &&
		!strings.EqualFold(tokenType, p.ExpectedTokenType) {
		return grantResponse{}, fmt.Errorf("%w: token_type %q, expected %q", ErrMalformedResponse, tokenType, p.ExpectedTokenType)
	}

	expiresIn := p.DefaultExpiresIn
	if secs, ok := lookupNumber(doc, p.ExpiresInPath); ok {
		if secs <= 0 {
			return grantResponse{}, fmt.Errorf("%w: %q is not positive", ErrMalformedResponse, p.ExpiresInPath)
		}
		expiresIn = time.Duration(secs) * time.Second
	}

	return grantResponse{AccessToken: token, TokenType: tokenType, ExpiresIn: expiresIn}, nil
}

// lookupPath walks a dot-separated path through nested JSON objects.
func lookupPath(doc map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	var cur any = doc
	for _, seg := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func lookupString(doc map[string]any, path string) (string, bool) {
	v, ok := lookupPath(doc, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func lookupNumber(doc map[string]any, path string) (float64, bool) {
	v, ok := lookupPath(doc, path)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// redactURLError strips the URL from transport errors. *url.Error embeds the
// request URL, which is safe here, but the wrapped error can carry resolver
// and proxy detail we would rather not fan out into logs verbatim.
func redactURLError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return fmt.Sprintf("%s %s: %v", uerr.Op, uerr.URL, uerr.Err)
	}
	return err.Error()
}
