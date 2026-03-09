package jwtx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteJWKS_KeyFunc(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := ComputeKIDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := NewJWKFromPublicKey(pub, kid)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{*jwk}})
	}))
	defer srv.Close()

	remote := NewRemoteJWKS(srv.URL, WithCacheTTL(1*time.Minute))

	// Sign a token and verify via remote KeyFunc.
	kp := &KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "EdDSA",
		KID:        kid,
	}
	token, err := Sign(kp, map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatal(err)
	}

	vt, err := Verify(token, remote.KeyFunc(), nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if vt.Claims["sub"] != "alice" {
		t.Fatalf("sub = %v, want alice", vt.Claims["sub"])
	}
}

func TestRemoteJWKS_CacheTTL(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := ComputeKIDFromPublicKey(pub)
	jwk, _ := NewJWKFromPublicKey(pub, kid)

	var fetchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{*jwk}})
	}))
	defer srv.Close()

	remote := NewRemoteJWKS(srv.URL, WithCacheTTL(1*time.Hour))

	// First call fetches.
	kf := remote.KeyFunc()
	if _, err := kf(kid, "EdDSA"); err != nil {
		t.Fatal(err)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1", fetchCount.Load())
	}

	// Second call uses cache.
	if _, err := kf(kid, "EdDSA"); err != nil {
		t.Fatal(err)
	}
	if fetchCount.Load() != 1 {
		t.Fatalf("fetch count = %d, want 1 (cached)", fetchCount.Load())
	}
}

func TestRemoteJWKS_KeyRotation(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	kid1, _ := ComputeKIDFromPublicKey(pub1)
	jwk1, _ := NewJWKFromPublicKey(pub1, kid1)

	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	kid2, _ := ComputeKIDFromPublicKey(pub2)
	jwk2, _ := NewJWKFromPublicKey(pub2, kid2)

	var fetchCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n <= 1 {
			// First fetch returns only key1.
			_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{*jwk1}})
		} else {
			// Subsequent fetches return both keys (rotation).
			_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{*jwk1, *jwk2}})
		}
	}))
	defer srv.Close()

	remote := NewRemoteJWKS(srv.URL, WithCacheTTL(1*time.Hour))
	kf := remote.KeyFunc()

	// Fetch key1 — populates cache.
	if _, err := kf(kid1, "EdDSA"); err != nil {
		t.Fatal(err)
	}

	// Request key2 — not in cache, triggers refetch.
	key, err := kf(kid2, "EdDSA")
	if err != nil {
		t.Fatalf("key rotation lookup failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key after rotation")
	}
	// Should have fetched twice (initial + rotation refetch).
	if fetchCount.Load() < 2 {
		t.Fatalf("fetch count = %d, want >= 2", fetchCount.Load())
	}
}

func TestRemoteJWKS_NoMatchingKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{}})
	}))
	defer srv.Close()

	remote := NewRemoteJWKS(srv.URL)
	_, err := remote.KeyFunc()("nonexistent", "RS256")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestRemoteJWKS_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	remote := NewRemoteJWKS(srv.URL)
	_, err := remote.KeyFunc()("kid", "RS256")
	if err == nil {
		t.Fatal("expected error for server error")
	}
}
