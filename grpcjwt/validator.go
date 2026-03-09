// Package grpcjwt provides JWT/JWKS validation for inbound gRPC calls.
// It supports both remote JWKS and static PEM public keys, and exposes
// a standard unary interceptor and subject extraction helper.
package grpcjwt

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ledatu/csar-core/jwtx"
)

// Config configures the gRPC JWT validator.
type Config struct {
	JWKSURL       string
	PublicKeyFile string
	Issuer        string
	Audience      string
	ClockSkew     time.Duration
	SubjectClaim  string
	CacheTTL      time.Duration
}

// Validator validates JWT tokens and extracts the subject claim.
type Validator struct {
	keyFunc      jwtx.KeyFunc
	verifyCfg    *jwtx.VerifyConfig
	subjectClaim string
	logger       *slog.Logger
}

// NewValidator creates a Validator from Config.
// It configures either a remote JWKS resolver or a static public key.
func NewValidator(cfg *Config, logger *slog.Logger) (*Validator, error) {
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}

	v := &Validator{
		subjectClaim: cfg.SubjectClaim,
		logger:       logger,
		verifyCfg: &jwtx.VerifyConfig{
			RequiredIssuer:   cfg.Issuer,
			RequiredAudience: cfg.Audience,
			ClockSkew:        cfg.ClockSkew,
		},
	}

	switch {
	case cfg.JWKSURL != "":
		remote := jwtx.NewRemoteJWKS(
			cfg.JWKSURL,
			jwtx.WithCacheTTL(cfg.CacheTTL),
			jwtx.WithLogger(logger.With("component", "jwks")),
		)
		v.keyFunc = remote.KeyFunc()
		logger.Info("grpcjwt: JWKS resolver configured", "url", cfg.JWKSURL)

	case cfg.PublicKeyFile != "":
		pub, err := loadPublicKey(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("grpcjwt: loading public key: %w", err)
		}
		v.keyFunc = func(_, _ string) (crypto.PublicKey, error) {
			return pub, nil
		}
		logger.Info("grpcjwt: static public key loaded", "file", cfg.PublicKeyFile)

	default:
		return nil, fmt.Errorf("grpcjwt: one of JWKSURL or PublicKeyFile is required")
	}

	return v, nil
}

// ValidateToken validates a JWT and returns the subject claim.
func (v *Validator) ValidateToken(tokenString string) (string, error) {
	vt, err := jwtx.Verify(tokenString, v.keyFunc, v.verifyCfg)
	if err != nil {
		return "", err
	}

	sub, ok := vt.Claims[v.subjectClaim]
	if !ok {
		return "", fmt.Errorf("grpcjwt: claim %q not found in token", v.subjectClaim)
	}

	subStr, ok := sub.(string)
	if !ok {
		return "", fmt.Errorf("grpcjwt: claim %q is not a string", v.subjectClaim)
	}

	v.logger.Debug("token validated",
		"sub", subStr,
		"kid", vt.Header["kid"],
		"alg", vt.Header["alg"],
	)

	return subStr, nil
}

func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
