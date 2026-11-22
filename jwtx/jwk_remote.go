package jwtx

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// RemoteJWKS fetches and caches keys from a JWKS URL.
// It provides a KeyFunc suitable for use with Verify.
type RemoteJWKS struct {
	url    string
	client *http.Client
	logger *slog.Logger

	mu    sync.RWMutex
	cache *remoteJWKSCache
	ttl   time.Duration
}

type remoteJWKSCache struct {
	keys      []JWK
	fetchedAt time.Time
}

// RemoteJWKSOption configures a RemoteJWKS.
type RemoteJWKSOption func(*RemoteJWKS)

// WithCacheTTL sets the JWKS cache lifetime. Default: 5 minutes.
func WithCacheTTL(ttl time.Duration) RemoteJWKSOption {
	return func(r *RemoteJWKS) { r.ttl = ttl }
}

// WithHTTPClient sets the HTTP client used for JWKS fetches.
func WithHTTPClient(client *http.Client) RemoteJWKSOption {
	return func(r *RemoteJWKS) { r.client = client }
}

// WithLogger sets the logger for JWKS fetch events.
func WithLogger(logger *slog.Logger) RemoteJWKSOption {
	return func(r *RemoteJWKS) { r.logger = logger }
}

// NewRemoteJWKS creates a remote JWKS resolver that fetches keys from the
// given URL and caches them for the configured TTL.
func NewRemoteJWKS(jwksURL string, opts ...RemoteJWKSOption) *RemoteJWKS {
	r := &RemoteJWKS{
		url:    jwksURL,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: slog.Default(),
		ttl:    5 * time.Minute,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// KeyFunc returns a KeyFunc that resolves public keys from the remote JWKS.
// On a kid cache miss it refetches once to handle key rotation.
func (r *RemoteJWKS) KeyFunc() KeyFunc {
	return r.KeyFuncContext(context.Background())
}

// KeyFuncContext shares the existing cache while bounding any fetch/refresh by
// the operation's context, including kid misses during key rotation.
func (r *RemoteJWKS) KeyFuncContext(ctx context.Context) KeyFunc {
	return func(kid, alg string) (crypto.PublicKey, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		jwk, err := r.findKey(ctx, kid, alg)
		if err != nil {
			return nil, err
		}
		return JWKToPublicKey(jwk)
	}
}

// findKey looks up a key by kid/alg from the cache, refetching on miss.
func (r *RemoteJWKS) findKey(ctx context.Context, kid, alg string) (*JWK, error) {
	keys, err := r.getJWKS(ctx)
	if err != nil {
		return nil, err
	}

	if key := matchKey(keys, kid, alg); key != nil {
		return key, nil
	}

	// kid not found — invalidate cache and refetch (key rotation).
	r.mu.Lock()
	r.cache = nil
	r.mu.Unlock()

	keys, err = r.getJWKS(ctx)
	if err != nil {
		return nil, err
	}

	if key := matchKey(keys, kid, alg); key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("jwtx: no matching key for kid=%q alg=%q", kid, alg)
}

// getJWKS returns cached keys or fetches from the URL.
func (r *RemoteJWKS) getJWKS(ctx context.Context) ([]JWK, error) {
	r.mu.RLock()
	if r.cache != nil && time.Since(r.cache.fetchedAt) < r.ttl {
		keys := r.cache.keys
		r.mu.RUnlock()
		return keys, nil
	}
	r.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwtx: invalid JWKS request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwtx: fetching JWKS from %s: %w", r.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwtx: JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks JWKS
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return nil, fmt.Errorf("jwtx: JWKS response unavailable or too large")
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("jwtx: decoding JWKS response: %w", err)
	}

	r.mu.Lock()
	r.cache = &remoteJWKSCache{
		keys:      jwks.Keys,
		fetchedAt: time.Now(),
	}
	r.mu.Unlock()

	r.logger.Debug("JWKS fetched", "url", r.url, "keys", len(jwks.Keys))
	return jwks.Keys, nil
}

// matchKey finds a JWK matching kid and alg.
func matchKey(keys []JWK, kid, alg string) *JWK {
	for i := range keys {
		k := &keys[i]
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		return k
	}
	return nil
}
