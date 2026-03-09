package jwtx

import (
	"crypto/ed25519"
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
