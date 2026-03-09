package jwtx

import (
	"crypto"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerify_EdDSA_SignAndVerify(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"sub": "u1",
		"iss": "test",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	vt, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		RequiredIssuer: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if vt.Claims["sub"] != "u1" {
		t.Fatalf("sub = %v", vt.Claims["sub"])
	}
}

func TestVerify_RS256_SignAndVerify(t *testing.T) {
	kp, _ := GenerateKeyPair("RS256")
	token := mustSign(t, kp, jwt.MapClaims{
		"sub": "u2",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerify_Expired(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, nil)
	if err == nil {
		t.Fatal("expected expiration error")
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"nbf": jwt.NewNumericDate(time.Now().Add(time.Hour)),
		"exp": jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, nil)
	if err == nil {
		t.Fatal("expected nbf error")
	}
}

func TestVerify_ClockSkew(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(-10 * time.Second)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		ClockSkew: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected skew to tolerate: %v", err)
	}
}

func TestVerify_IssuerMismatch(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"iss": "wrong",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		RequiredIssuer: "right",
	})
	if err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestVerify_AudienceMismatch(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"aud": []string{"other"},
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		RequiredAudience: "csar",
	})
	if err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestVerify_AudienceStringMatch(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"aud": "csar",
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		RequiredAudience: "csar",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerify_AllowedAlgorithms(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp.PublicKey, &VerifyConfig{
		AllowedAlgorithms: []string{"RS256"},
	})
	if err == nil {
		t.Fatal("expected algorithm rejection")
	}
}

func TestVerify_RejectsNone(t *testing.T) {
	// Manually craft a token with alg=none
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
	kp, _ := GenerateKeyPair("EdDSA")
	_, err := VerifyWithKey(noneToken, kp.PublicKey, nil)
	if err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair("EdDSA")
	kp2, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp1, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	_, err := VerifyWithKey(token, kp2.PublicKey, nil)
	if err == nil {
		t.Fatal("expected signature failure with wrong key")
	}
}

func TestVerify_KeyFunc(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	token := mustSign(t, kp, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	// KeyFunc receives the correct kid
	called := false
	_, err := Verify(token, func(kid, alg string) (crypto.PublicKey, error) {
		called = true
		if kid != kp.KID {
			t.Fatalf("kid = %q, want %q", kid, kp.KID)
		}
		if alg != "EdDSA" {
			t.Fatalf("alg = %q, want EdDSA", alg)
		}
		return kp.PublicKey, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("keyFunc was not called")
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	kp, _ := GenerateKeyPair("EdDSA")
	_, err := VerifyWithKey("not.a.valid.jwt", kp.PublicKey, nil)
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

// Cross-verify: sign with jwtx, verify with golang-jwt, and vice versa.
func TestCrossVerify_SignJwtxVerifyGolangJWT(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			kp, _ := GenerateKeyPair(alg)
			token := mustSign(t, kp, jwt.MapClaims{
				"sub": "cross",
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})

			parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
				return kp.PublicKey, nil
			})
			if err != nil {
				t.Fatalf("golang-jwt parse: %v", err)
			}
			if !parsed.Valid {
				t.Fatal("not valid")
			}
		})
	}
}

func TestCrossVerify_SignGolangJWTVerifyJwtx(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			kp, _ := GenerateKeyPair(alg)

			method, key, _ := signingMethodAndKey(kp)
			claims := jwt.MapClaims{
				"sub": "cross2",
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			}
			tok := jwt.NewWithClaims(method, claims)
			tok.Header["kid"] = kp.KID
			token, err := tok.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}

			vt, err := VerifyWithKey(token, kp.PublicKey, nil)
			if err != nil {
				t.Fatalf("jwtx verify: %v", err)
			}
			if vt.Claims["sub"] != "cross2" {
				t.Fatalf("sub = %v", vt.Claims["sub"])
			}
		})
	}
}

func mustSign(t *testing.T, kp *KeyPair, claims jwt.MapClaims) string {
	t.Helper()
	token, err := Sign(kp, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
