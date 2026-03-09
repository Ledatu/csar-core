package jwtx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// KeyFunc resolves a public key from a token's kid and alg header values.
type KeyFunc func(kid, alg string) (crypto.PublicKey, error)

// VerifyConfig configures token verification.
type VerifyConfig struct {
	AllowedAlgorithms []string      // if non-empty, only these algs are accepted
	RequiredIssuer    string        // if non-empty, iss must match
	RequiredAudience  string        // if non-empty, aud must contain this value
	ClockSkew         time.Duration // tolerance for exp/nbf checks
}

// VerifiedToken is the result of successful verification.
type VerifiedToken struct {
	Header map[string]any
	Claims map[string]any
}

// Verify parses a compact JWT, verifies its signature using keyFunc, and
// validates standard time claims (exp, nbf) and optionally iss/aud.
//
// The implementation is stdlib-only and supports:
//   - RSA: RS256, RS384, RS512
//   - ECDSA: ES256, ES384, ES512
//   - EdDSA: Ed25519 (OKP)
func Verify(tokenString string, keyFunc KeyFunc, cfg *VerifyConfig) (*VerifiedToken, error) {
	if cfg == nil {
		cfg = &VerifyConfig{}
	}

	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("jwtx: malformed JWT: expected 3 dot-separated parts")
	}

	// Decode header.
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("jwtx: parsing header: %w", err)
	}

	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)

	// Reject "none" algorithm.
	if strings.EqualFold(alg, "none") {
		return nil, errors.New("jwtx: unsecured JWT (alg=none) rejected")
	}

	// Check allowed algorithms.
	if len(cfg.AllowedAlgorithms) > 0 {
		allowed := false
		for _, a := range cfg.AllowedAlgorithms {
			if a == alg {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("jwtx: algorithm %q not in allowed set", alg)
		}
	}

	// Resolve key.
	pub, err := keyFunc(kid, alg)
	if err != nil {
		return nil, fmt.Errorf("jwtx: key lookup: %w", err)
	}

	// Verify signature.
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding signature: %w", err)
	}
	if err := verifySig(alg, pub, signingInput, signature); err != nil {
		return nil, fmt.Errorf("jwtx: %w", err)
	}

	// Decode claims.
	claimBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, fmt.Errorf("jwtx: parsing claims: %w", err)
	}

	// Validate time claims.
	now := time.Now()
	skew := cfg.ClockSkew

	if exp, ok := numericClaim(claims, "exp"); ok {
		if now.After(time.Unix(exp, 0).Add(skew)) {
			return nil, errors.New("jwtx: token expired")
		}
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if now.Before(time.Unix(nbf, 0).Add(-skew)) {
			return nil, errors.New("jwtx: token not yet valid (nbf)")
		}
	}

	// Validate issuer.
	if cfg.RequiredIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != cfg.RequiredIssuer {
			return nil, fmt.Errorf("jwtx: issuer mismatch: got %q, want %q", iss, cfg.RequiredIssuer)
		}
	}

	// Validate audience.
	if cfg.RequiredAudience != "" {
		if !audienceContains(claims["aud"], cfg.RequiredAudience) {
			return nil, fmt.Errorf("jwtx: audience mismatch: %q not found", cfg.RequiredAudience)
		}
	}

	return &VerifiedToken{Header: header, Claims: claims}, nil
}

// VerifyWithKey is a convenience for single-key verification.
func VerifyWithKey(tokenString string, pub crypto.PublicKey, cfg *VerifyConfig) (*VerifiedToken, error) {
	return Verify(tokenString, func(_, _ string) (crypto.PublicKey, error) {
		return pub, nil
	}, cfg)
}

// VerifyWithKeyRaw verifies a raw JWT signature (signingInput, signature bytes)
// against a public key and algorithm. This is useful when callers do their own
// JWT parsing but want to delegate cryptographic verification.
func VerifyWithKeyRaw(signingInput, signature []byte, pub crypto.PublicKey, alg string) error {
	return verifySig(alg, pub, signingInput, signature)
}

func numericClaim(claims map[string]any, key string) (int64, bool) {
	v, ok := claims[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func audienceContains(aud any, target string) bool {
	switch v := aud.(type) {
	case string:
		return v == target
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Signature verification (stdlib crypto)
// ---------------------------------------------------------------------------

func verifySig(alg string, pub crypto.PublicKey, signingInput, signature []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return verifyRSA(alg, pub, signingInput, signature)
	case strings.HasPrefix(alg, "ES"):
		return verifyECDSA(alg, pub, signingInput, signature)
	case alg == "EdDSA":
		return verifyEdDSA(pub, signingInput, signature)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifyRSA(alg string, pub crypto.PublicKey, signingInput, signature []byte) error {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected *rsa.PublicKey")
	}
	hashFunc := algToHash(alg)
	if hashFunc == 0 {
		return fmt.Errorf("unsupported RSA hash for %s", alg)
	}
	h := hashFunc.New()
	h.Write(signingInput)
	return rsa.VerifyPKCS1v15(rsaPub, hashFunc, h.Sum(nil), signature)
}

func verifyECDSA(alg string, pub crypto.PublicKey, signingInput, signature []byte) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected *ecdsa.PublicKey")
	}
	hashFunc := algToHash(alg)
	if hashFunc == 0 {
		return fmt.Errorf("unsupported ECDSA hash for %s", alg)
	}
	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	// JWT ECDSA signatures are r||s (raw, not ASN.1).
	keySize := (ecPub.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return errors.New("invalid ECDSA signature length")
	}
	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(ecPub, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

func verifyEdDSA(pub crypto.PublicKey, signingInput, signature []byte) error {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return errors.New("key type mismatch: expected ed25519.PublicKey")
	}
	if !ed25519.Verify(edPub, signingInput, signature) {
		return errors.New("EdDSA signature verification failed")
	}
	return nil
}

func algToHash(alg string) crypto.Hash {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256
	case "RS384", "ES384":
		return crypto.SHA384
	case "RS512", "ES512":
		return crypto.SHA512
	default:
		return 0
	}
}

func getCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}

// base64URLDecode decodes a base64url-encoded string, tolerant of missing padding.
func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
