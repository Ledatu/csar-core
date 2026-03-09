package jwtx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a single JSON Web Key (RFC 7517 / RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg,omitempty"`

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// OKP fields (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`

	// EC fields (ECDSA) — for verification from remote JWKS
	Y string `json:"y,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Marshal serialises the JWKS as indented JSON.
func (ks *JWKS) Marshal() ([]byte, error) {
	return json.MarshalIndent(ks, "", "  ")
}

// NewJWKFromPublicKey builds a JWK from a crypto.PublicKey with the given KID.
// Supported key types: *rsa.PublicKey and ed25519.PublicKey.
func NewJWKFromPublicKey(pub any, kid string) (*JWK, error) {
	switch key := pub.(type) {
	case ed25519.PublicKey:
		return &JWK{
			Kty: "OKP",
			Kid: kid,
			Use: "sig",
			Alg: "EdDSA",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(key),
		}, nil

	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil

	default:
		return nil, fmt.Errorf("jwtx: unsupported key type %T for JWK", pub)
	}
}

// JWKToPublicKey converts a JWK to a crypto.PublicKey.
// Supports RSA, EC (P-256, P-384, P-521), and OKP (Ed25519).
func JWKToPublicKey(jwk *JWK) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECPublicKey(jwk)
	case "OKP":
		return jwkToEdPublicKey(jwk)
	default:
		return nil, fmt.Errorf("jwtx: unsupported key type %q", jwk.Kty)
	}
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding RSA modulus: %w", err)
	}
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding RSA exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func jwkToECPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	curve, err := ecCurve(jwk.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding EC x: %w", err)
	}
	yBytes, err := base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding EC y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func jwkToEdPublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("jwtx: unsupported OKP curve %q", jwk.Crv)
	}
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("jwtx: decoding Ed25519 public key: %w", err)
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwtx: invalid Ed25519 public key length: %d", len(xBytes))
	}
	return ed25519.PublicKey(xBytes), nil
}

func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("jwtx: unsupported EC curve %q", crv)
	}
}

// NewJWKS builds a JWKS from one or more public keys. KIDs are derived
// automatically via ComputeKIDFromPublicKey.
func NewJWKS(keys ...any) (*JWKS, error) {
	jwks := &JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, pub := range keys {
		kid, err := ComputeKIDFromPublicKey(pub)
		if err != nil {
			return nil, err
		}
		jwk, err := NewJWKFromPublicKey(pub, kid)
		if err != nil {
			return nil, err
		}
		jwks.Keys = append(jwks.Keys, *jwk)
	}
	return jwks, nil
}
