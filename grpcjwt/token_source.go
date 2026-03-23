package grpcjwt

import (
	"context"
	"sync"
	"time"

	"github.com/ledatu/csar-core/jwtx"
)

const tokenRefreshBuffer = 30 * time.Second

// ServiceTokenSource implements grpc credentials.PerRPCCredentials by
// self-minting short-lived JWTs via jwtx.SignWithConfig. Tokens are
// cached and refreshed automatically before expiry.
//
// Use this to authenticate service-to-service gRPC calls (e.g. to csar-authz).
type ServiceTokenSource struct {
	mu      sync.Mutex
	kp      *jwtx.KeyPair
	cfg     *jwtx.SigningConfig
	subject string
	token   string
	expiry  time.Time
}

// NewServiceTokenSource creates a PerRPCCredentials that mints JWTs for
// the given service identity (e.g. "svc:aurumskynet-campaigns").
// The token is cached and refreshed 30s before the configured TTL expires.
func NewServiceTokenSource(kp *jwtx.KeyPair, subject string, cfg *jwtx.SigningConfig) *ServiceTokenSource {
	return &ServiceTokenSource{
		kp:      kp,
		cfg:     cfg,
		subject: subject,
	}
}

// GetRequestMetadata returns an authorization Bearer header with a cached
// or freshly minted JWT.
func (s *ServiceTokenSource) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	tok, err := s.cachedToken()
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

// RequireTransportSecurity returns true -- service tokens must only be
// sent over TLS-protected connections.
func (s *ServiceTokenSource) RequireTransportSecurity() bool { return true }

func (s *ServiceTokenSource) cachedToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiry) {
		return s.token, nil
	}

	tok, err := jwtx.SignWithConfig(s.kp, s.cfg, map[string]any{"sub": s.subject})
	if err != nil {
		return "", err
	}
	s.token = tok
	s.expiry = time.Now().Add(s.cfg.TTL - tokenRefreshBuffer)
	return tok, nil
}
