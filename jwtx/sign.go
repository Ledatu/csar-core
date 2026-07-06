package jwtx

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SigningConfig holds standard claims for token issuance.
type SigningConfig struct {
	Issuer   string
	Audience []string
	TTL      time.Duration
}

// Sign creates a JWT with arbitrary claims, setting the kid header from kp.
// The caller is responsible for all claim content.
func Sign(kp *KeyPair, claims jwt.MapClaims) (string, error) {
	method, key, err := signingMethodAndKey(kp)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kp.KID

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("jwtx: signing token: %w", err)
	}
	return signed, nil
}

// SignWithConfig creates a JWT populating iss, aud, iat, nbf, exp from cfg,
// then merging any extraClaims on top.
func SignWithConfig(kp *KeyPair, cfg *SigningConfig, extraClaims map[string]any) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(cfg.TTL)),
	}
	if cfg.Issuer != "" {
		claims["iss"] = cfg.Issuer
	}
	if len(cfg.Audience) > 0 {
		claims["aud"] = cfg.Audience
	}
	for k, v := range extraClaims {
		claims[k] = v
	}
	return Sign(kp, claims)
}

// SignHMAC creates an HMAC-signed JWT with arbitrary claims.
// The caller is responsible for all claim content.
func SignHMAC(secret []byte, alg string, claims jwt.MapClaims) (string, error) {
	method, err := hmacSigningMethod(alg)
	if err != nil {
		return "", err
	}
	if len(secret) == 0 {
		return "", fmt.Errorf("jwtx: hmac secret is empty")
	}

	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("jwtx: signing hmac token: %w", err)
	}
	return signed, nil
}

// SignHMACWithConfig creates an HMAC-signed JWT populating iss, aud, iat, nbf,
// exp from cfg, then merging any extraClaims on top.
func SignHMACWithConfig(secret []byte, alg string, cfg *SigningConfig, extraClaims map[string]any) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("jwtx: signing config is nil")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(cfg.TTL)),
	}
	if cfg.Issuer != "" {
		claims["iss"] = cfg.Issuer
	}
	if len(cfg.Audience) > 0 {
		claims["aud"] = cfg.Audience
	}
	for k, v := range extraClaims {
		claims[k] = v
	}
	return SignHMAC(secret, alg, claims)
}

func signingMethodAndKey(kp *KeyPair) (jwt.SigningMethod, any, error) {
	switch kp.Algorithm {
	case "EdDSA":
		return jwt.SigningMethodEdDSA, kp.PrivateKey, nil
	case "RS256":
		return jwt.SigningMethodRS256, kp.PrivateKey, nil
	default:
		return nil, nil, fmt.Errorf("jwtx: unsupported signing algorithm %q", kp.Algorithm)
	}
}

func hmacSigningMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case "HS256":
		return jwt.SigningMethodHS256, nil
	default:
		return nil, fmt.Errorf("jwtx: unsupported hmac signing algorithm %q", alg)
	}
}
