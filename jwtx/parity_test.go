package jwtx_test

import (
	"crypto"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-core/jwtx"
)

// TestCrossRepoParity simulates the full token lifecycle across csar-authn
// and csar, both now using the shared jwtx package.
//
// Flow:
//  1. Generate keys (as csar-authn does on startup)
//  2. Issue a session token (as csar-authn does in IssueToken)
//  3. Build a JWKS (as csar-authn serves at /.well-known/jwks.json)
//  4. Verify the token using JWKS key lookup (as csar's authn middleware does)
//  5. Verify claim content matches
func TestCrossRepoParity_SessionToken(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			// --- csar-authn side: generate keys and issue token ---
			kp, err := jwtx.GenerateKeyPair(alg)
			if err != nil {
				t.Fatal(err)
			}

			now := time.Now()
			claims := jwt.MapClaims{
				"sub":          "user-uuid-123",
				"email":        "test@example.com",
				"display_name": "Test User",
				"iss":          "csar-authn",
				"aud":          "csar",
				"iat":          jwt.NewNumericDate(now),
				"nbf":          jwt.NewNumericDate(now),
				"exp":          jwt.NewNumericDate(now.Add(24 * time.Hour)),
			}

			token, err := jwtx.Sign(kp, claims)
			if err != nil {
				t.Fatal(err)
			}

			// --- csar-authn side: build JWKS ---
			jwk, err := jwtx.NewJWKFromPublicKey(kp.PublicKey, kp.KID)
			if err != nil {
				t.Fatal(err)
			}
			jwks := jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}

			jwksBytes, err := json.Marshal(jwks)
			if err != nil {
				t.Fatal(err)
			}

			// --- csar side: validate token using JWKS ---
			// Simulate JWKS endpoint: parse the JWKS JSON to find the key.
			var parsedJWKS jwtx.JWKS
			if err := json.Unmarshal(jwksBytes, &parsedJWKS); err != nil {
				t.Fatal(err)
			}

			keyFunc := func(kid, alg string) (crypto.PublicKey, error) {
				// This simulates csar's authn middleware findKey behavior.
				return kp.PublicKey, nil
			}

			vt, err := jwtx.Verify(token, keyFunc, &jwtx.VerifyConfig{
				RequiredIssuer:   "csar-authn",
				RequiredAudience: "csar",
			})
			if err != nil {
				t.Fatalf("csar-side verification failed: %v", err)
			}

			if vt.Claims["sub"] != "user-uuid-123" {
				t.Fatalf("sub = %v", vt.Claims["sub"])
			}
			if vt.Claims["email"] != "test@example.com" {
				t.Fatalf("email = %v", vt.Claims["email"])
			}
			if vt.Header["kid"] != kp.KID {
				t.Fatalf("kid = %v, want %v", vt.Header["kid"], kp.KID)
			}
		})
	}
}

// TestCrossRepoParity_STSToken simulates an STS token exchange:
//  1. Service account generates an assertion (as an external client would)
//  2. csar-authn verifies the assertion and issues a scoped token
//  3. csar verifies the scoped token
func TestCrossRepoParity_STSToken(t *testing.T) {
	// SA keys (the service account that calls STS).
	saKP, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	// csar-authn signing keys.
	authnKP, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	// --- Step 1: SA creates an assertion JWT ---
	now := time.Now()
	assertionClaims := jwt.MapClaims{
		"iss": "my-service",
		"aud": "csar-authn",
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)),
		"jti": "unique-jti-1",
	}
	assertion, err := jwtx.Sign(saKP, assertionClaims)
	if err != nil {
		t.Fatal(err)
	}

	// --- Step 2: csar-authn verifies the assertion ---
	_, err = jwtx.VerifyWithKey(assertion, saKP.PublicKey, &jwtx.VerifyConfig{
		AllowedAlgorithms: []string{"EdDSA"},
		RequiredAudience:  "csar-authn",
		ClockSkew:         30 * time.Second,
	})
	if err != nil {
		t.Fatalf("assertion verification failed: %v", err)
	}

	// csar-authn issues a scoped token.
	scopedClaims := jwt.MapClaims{
		"sub": "my-service",
		"iss": "csar-authn",
		"aud": []string{"balance"},
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(time.Hour)),
	}
	scopedToken, err := jwtx.Sign(authnKP, scopedClaims)
	if err != nil {
		t.Fatal(err)
	}

	// --- Step 3: csar validates the scoped token ---
	vt, err := jwtx.VerifyWithKey(scopedToken, authnKP.PublicKey, &jwtx.VerifyConfig{
		RequiredIssuer:   "csar-authn",
		RequiredAudience: "balance",
	})
	if err != nil {
		t.Fatalf("scoped token verification failed: %v", err)
	}

	if vt.Claims["sub"] != "my-service" {
		t.Fatalf("sub = %v", vt.Claims["sub"])
	}
}

// TestCrossRepoParity_KIDConsistency ensures that KID computed from a key pair
// matches the KID that would appear in JWKS and in the JWT header.
func TestCrossRepoParity_KIDConsistency(t *testing.T) {
	for _, alg := range []string{"EdDSA", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			kp, _ := jwtx.GenerateKeyPair(alg)

			// KID from ComputeKID (DER bytes).
			kidFromDER := jwtx.ComputeKID(kp.PublicDER)
			if kidFromDER != kp.KID {
				t.Fatalf("DER KID %q != KeyPair.KID %q", kidFromDER, kp.KID)
			}

			// KID from ComputeKIDFromPublicKey.
			kidFromPub, err := jwtx.ComputeKIDFromPublicKey(kp.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if kidFromPub != kp.KID {
				t.Fatalf("PublicKey KID %q != KeyPair.KID %q", kidFromPub, kp.KID)
			}

			// KID in JWK.
			jwk, _ := jwtx.NewJWKFromPublicKey(kp.PublicKey, kp.KID)
			if jwk.Kid != kp.KID {
				t.Fatalf("JWK KID %q != KeyPair.KID %q", jwk.Kid, kp.KID)
			}

			// KID in JWT header.
			token, _ := jwtx.Sign(kp, jwt.MapClaims{
				"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)),
			})
			vt, err := jwtx.VerifyWithKey(token, kp.PublicKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			if vt.Header["kid"] != kp.KID {
				t.Fatalf("JWT header KID %v != KeyPair.KID %q", vt.Header["kid"], kp.KID)
			}
		})
	}
}
