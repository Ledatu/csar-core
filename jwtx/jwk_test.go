package jwtx

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
