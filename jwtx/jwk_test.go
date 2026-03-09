package jwtx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestNewJWKFromPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := NewJWKFromPublicKey(pub, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "OKP" {
		t.Fatalf("kty = %q, want OKP", jwk.Kty)
	}
	if jwk.Alg != "EdDSA" {
		t.Fatalf("alg = %q, want EdDSA", jwk.Alg)
	}
	if jwk.Crv != "Ed25519" {
		t.Fatalf("crv = %q, want Ed25519", jwk.Crv)
	}
	if jwk.Kid != "test-kid" {
		t.Fatalf("kid = %q, want test-kid", jwk.Kid)
	}
	if jwk.X == "" {
		t.Fatal("x is empty")
	}
}

func TestNewJWKFromPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := NewJWKFromPublicKey(&key.PublicKey, "rsa-kid")
	if err != nil {
		t.Fatal(err)
	}
	if jwk.Kty != "RSA" {
		t.Fatalf("kty = %q, want RSA", jwk.Kty)
	}
	if jwk.N == "" || jwk.E == "" {
		t.Fatal("N or E is empty")
	}
}

func TestNewJWKFromPublicKey_Unsupported(t *testing.T) {
	_, err := NewJWKFromPublicKey("bad", "kid")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewJWKS(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	jwks, err := NewJWKS(pub, &rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(jwks.Keys))
	}
}

func TestJWKToPublicKey_RSA_Roundtrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := NewJWKFromPublicKey(&key.PublicKey, "rsa-rt")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(key.N) != 0 {
		t.Fatal("RSA modulus mismatch after roundtrip")
	}
	if rsaPub.E != key.E {
		t.Fatal("RSA exponent mismatch after roundtrip")
	}
}

func TestJWKToPublicKey_Ed25519_Roundtrip(t *testing.T) {
	origPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := NewJWKFromPublicKey(origPub, "ed-rt")
	if err != nil {
		t.Fatal(err)
	}

	pub, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", pub)
	}
	if !origPub.Equal(edPub) {
		t.Fatal("Ed25519 key mismatch after roundtrip")
	}
}

func TestJWKToPublicKey_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Get the uncompressed point via crypto/ecdh (avoids deprecated big.Int fields).
	ecdhKey, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	// ECDH Bytes() returns the uncompressed point: 0x04 || X || Y.
	raw := ecdhKey.Bytes()
	coordLen := (len(raw) - 1) / 2
	xBytes := raw[1 : 1+coordLen]
	yBytes := raw[1+coordLen:]

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64RawURLEncode(xBytes, coordLen),
		Y:   base64RawURLEncode(yBytes, coordLen),
	}

	pub, err := JWKToPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	// Roundtrip: convert both to ECDH and compare bytes.
	gotECDH, err := ecPub.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	if !ecdhKey.Equal(gotECDH) {
		t.Fatal("ECDSA key mismatch")
	}
}

func TestJWKToPublicKey_UnsupportedType(t *testing.T) {
	jwk := &JWK{Kty: "unknown"}
	_, err := JWKToPublicKey(jwk)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// base64RawURLEncode left-pads b to size bytes then encodes.
func base64RawURLEncode(b []byte, size int) string {
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func TestJWKS_Marshal(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwks, err := NewJWKS(pub)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jwks.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var roundtrip JWKS
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if len(roundtrip.Keys) != 1 {
		t.Fatalf("expected 1 key after roundtrip, got %d", len(roundtrip.Keys))
	}
}
