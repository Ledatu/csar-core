// Package stsclient exchanges JWT assertions for access tokens at csar-authn's
// STS endpoint (POST /sts/token) and optionally wraps an http.RoundTripper to
// inject Bearer tokens for service-to-service HTTP calls through the router.
package stsclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
)

const tokenRefreshBuffer = 30 * time.Second

// refreshWindowForExpiresIn returns how long to cache an access token before refreshing.
// Long-lived tokens use a 30s buffer before nominal expiry; short TTLs use half the lifetime.
func refreshWindowForExpiresIn(expiresIn int) time.Duration {
	ttl := time.Duration(expiresIn) * time.Second
	switch {
	case ttl > tokenRefreshBuffer:
		return ttl - tokenRefreshBuffer
	case ttl > 0:
		return ttl / 2
	default:
		return 0
	}
}

// Config configures the STS token exchange client.
type Config struct {
	// STSEndpoint is the full URL for POST /sts/token (e.g. https://authn:8081/sts/token).
	STSEndpoint string
	// Audience is the requested access token audience (e.g. csar-authz-svc).
	Audience string
	// ServiceName is the service account name used as JWT iss (e.g. svc:aurumskynet-campaigns).
	ServiceName string
	// AssertionAudience is the aud claim on the JWT assertion — must match csar-authn's JWT issuer (base_url).
	AssertionAudience string
	// KeyPair signs the JWT-bearer assertion.
	KeyPair *jwtx.KeyPair
	// AssertionTTL bounds the signed assertion lifetime (must be <= STS assertion_max_age).
	AssertionTTL time.Duration
	// HTTPClient is used for the token exchange. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// TokenSource caches STS access tokens and refreshes before expiry.
type TokenSource struct {
	cfg    Config
	client *http.Client
	logger *slog.Logger

	mu       sync.Mutex
	token    string
	expiry   time.Time
	assertTTL time.Duration
}

// New creates a TokenSource. AssertionTTL defaults to 4m if zero.
func New(cfg *Config) (*TokenSource, error) {
	if cfg == nil {
		return nil, fmt.Errorf("stsclient: cfg is nil")
	}
	if cfg.STSEndpoint == "" {
		return nil, fmt.Errorf("stsclient: STSEndpoint is required")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("stsclient: Audience is required")
	}
	if cfg.ServiceName == "" {
		return nil, fmt.Errorf("stsclient: ServiceName is required")
	}
	if cfg.AssertionAudience == "" {
		return nil, fmt.Errorf("stsclient: AssertionAudience is required")
	}
	if cfg.KeyPair == nil {
		return nil, fmt.Errorf("stsclient: KeyPair is required")
	}
	ttl := cfg.AssertionTTL
	if ttl == 0 {
		ttl = 4 * time.Minute
	}
	c := cfg.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &TokenSource{
		cfg:       *cfg,
		client:    c,
		logger:    log,
		assertTTL: ttl,
	}, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Token returns a valid Bearer access token, exchanging a fresh assertion when needed.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token != "" && time.Now().Before(ts.expiry) {
		return ts.token, nil
	}

	assertion, err := ts.signAssertion()
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	form.Set("audience", ts.cfg.Audience)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.cfg.STSEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("stsclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("stsclient: sts request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("stsclient: read sts body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("stsclient: sts status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("stsclient: decode sts response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("stsclient: empty access_token in sts response")
	}

	refresh := refreshWindowForExpiresIn(tr.ExpiresIn)
	ts.token = tr.AccessToken
	ts.expiry = time.Now().Add(refresh)
	return ts.token, nil
}

func (ts *TokenSource) signAssertion() (string, error) {
	now := time.Now()
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("stsclient: jti: %w", err)
	}
	exp := now.Add(ts.assertTTL)
	claims := jwt.MapClaims{
		"iss": ts.cfg.ServiceName,
		"aud": ts.cfg.AssertionAudience,
		"sub": ts.cfg.ServiceName,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": jti.String(),
	}
	tok, err := jwtx.Sign(ts.cfg.KeyPair, claims)
	if err != nil {
		return "", fmt.Errorf("stsclient: sign assertion: %w", err)
	}
	return tok, nil
}

// bearerTransport injects X-Csar-Authorization: Bearer <token> from TokenSource.
// Authorization is left untouched so callers can pass an upstream credential
// through the router on routes that proxy it verbatim.
type bearerTransport struct {
	base   http.RoundTripper
	source *TokenSource
}

// Transport returns an http.RoundTripper that adds Bearer tokens from ts to each request.
func (ts *TokenSource) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &bearerTransport{base: base, source: ts}
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	tok, err := t.source.Token(ctx)
	if err != nil {
		return nil, err
	}
	req2 := req.Clone(ctx)
	req2.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+tok)
	return t.base.RoundTrip(req2)
}
