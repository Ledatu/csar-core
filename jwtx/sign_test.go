package jwtx

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSign_EdDSA(t *testing.T) {
	kp, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"sub": "user-1",
		"iss": "test",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := Sign(kp, claims)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	// Verify with golang-jwt to confirm interoperability.
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return kp.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("golang-jwt parse failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
	if parsed.Header["kid"] != kp.KID {
		t.Fatalf("kid = %v, want %v", parsed.Header["kid"], kp.KID)
	}
}

func TestSign_RS256(t *testing.T) {
	kp, err := GenerateKeyPair("RS256")
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"sub": "user-2",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := Sign(kp, claims)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return kp.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("golang-jwt parse failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
}

func TestSignWithConfig(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	cfg := &SigningConfig{
		Issuer:   "csar-authn",
		Audience: []string{"csar"},
		TTL:      time.Hour,
	}

	token, err := SignWithConfig(kp, cfg, map[string]any{
		"sub":   "user-3",
		"email": "test@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return kp.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	if claims["iss"] != "csar-authn" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "user-3" {
		t.Fatalf("sub = %v", claims["sub"])
	}
}

func TestSignHMACWithConfig(t *testing.T) {
	secret := []byte("test-secret")
	cfg := &SigningConfig{
		Issuer:   "csar-authn",
		Audience: []string{"telegram-webapp"},
		TTL:      time.Hour,
	}

	token, err := SignHMACWithConfig(secret, "HS256", cfg, map[string]any{
		"id": int64(12345),
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			t.Fatalf("method = %v, want HS256", token.Method.Alg())
		}
		return secret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	if claims["iss"] != "csar-authn" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["id"] != float64(12345) {
		t.Fatalf("id = %v", claims["id"])
	}
}

func TestSignHMACRejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := SignHMAC([]byte("secret"), "HS384", jwt.MapClaims{"sub": "user"})
	if err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}
