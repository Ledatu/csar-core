package jwtx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair_EdDSA(t *testing.T) {
	kp, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Algorithm != "EdDSA" {
		t.Fatalf("algorithm = %q, want EdDSA", kp.Algorithm)
	}
	if len(kp.KID) != 16 {
		t.Fatalf("kid length = %d, want 16", len(kp.KID))
	}
	if kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Fatal("keys are nil")
	}
	if len(kp.PublicDER) == 0 {
		t.Fatal("PublicDER is empty")
	}
}

func TestGenerateKeyPair_RS256(t *testing.T) {
	kp, err := GenerateKeyPair("RS256")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Algorithm != "RS256" {
		t.Fatalf("algorithm = %q, want RS256", kp.Algorithm)
	}
	if len(kp.KID) != 16 {
		t.Fatalf("kid length = %d, want 16", len(kp.KID))
	}
}

func TestGenerateKeyPair_Unsupported(t *testing.T) {
	_, err := GenerateKeyPair("ES256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestLoadKeyPairFromPEM_RoundTrip(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			kp, err := GenerateKeyPair(alg)
			if err != nil {
				t.Fatal(err)
			}
			privPEM, pubPEM, err := MarshalKeyPairPEM(kp)
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			privPath := filepath.Join(dir, "priv.pem")
			pubPath := filepath.Join(dir, "pub.pem")
			if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
				t.Fatal(err)
			}

			loaded, err := LoadKeyPairFromPEM(privPath, pubPath)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Algorithm != kp.Algorithm {
				t.Fatalf("algorithm = %q, want %q", loaded.Algorithm, kp.Algorithm)
			}
			if loaded.KID != kp.KID {
				t.Fatalf("kid = %q, want %q", loaded.KID, kp.KID)
			}
		})
	}
}

func TestParseKeyPairPEM(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	privPEM, pubPEM, _ := MarshalKeyPairPEM(kp)

	parsed, err := ParseKeyPairPEM(privPEM, pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KID != kp.KID {
		t.Fatalf("kid mismatch: %q vs %q", parsed.KID, kp.KID)
	}
}

func TestParseKeyPairPEM_BadInput(t *testing.T) {
	_, err := ParseKeyPairPEM([]byte("bad"), []byte("bad"))
	if err == nil {
		t.Fatal("expected error for bad PEM")
	}
}

func TestDetectAlgorithm(t *testing.T) {
	ed, _ := GenerateKeyPair("EdDSA")
	alg, err := DetectAlgorithm(ed.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "EdDSA" {
		t.Fatalf("got %q", alg)
	}

	rs, _ := GenerateKeyPair("RS256")
	alg, err = DetectAlgorithm(rs.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if alg != "RS256" {
		t.Fatalf("got %q", alg)
	}
}
