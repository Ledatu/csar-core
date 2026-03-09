package jwtx

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestComputeKID_Deterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	kid1 := ComputeKID(der)
	kid2 := ComputeKID(der)
	if kid1 != kid2 {
		t.Fatalf("KID not deterministic: %q vs %q", kid1, kid2)
	}
	if len(kid1) != 16 {
		t.Fatalf("expected 16-char hex KID, got %d chars: %q", len(kid1), kid1)
	}
}

func TestComputeKIDFromPublicKey_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := ComputeKIDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(kid) != 16 {
		t.Fatalf("expected 16-char hex KID, got %d chars: %q", len(kid), kid)
	}

	der, _ := x509.MarshalPKIXPublicKey(pub)
	if kid != ComputeKID(der) {
		t.Fatal("ComputeKIDFromPublicKey and ComputeKID disagree")
	}
}

func TestComputeKIDFromPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := ComputeKIDFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(kid) != 16 {
		t.Fatalf("expected 16-char hex KID, got %d chars: %q", len(kid), kid)
	}
}

func TestComputeKIDFromPublicKey_Unsupported(t *testing.T) {
	_, err := ComputeKIDFromPublicKey("not-a-key")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}
