package grpcjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/jwtx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func testKeyAndServer(t *testing.T) (*jwtx.KeyPair, *httptest.Server) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := jwtx.ComputeKIDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	kp := &jwtx.KeyPair{
		PrivateKey: priv,
		PublicKey:  pub,
		Algorithm:  "EdDSA",
		KID:        kid,
	}

	jwk, err := jwtx.NewJWKFromPublicKey(pub, kid)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}})
	}))
	t.Cleanup(srv.Close)
	return kp, srv
}

func TestValidator_ValidateToken(t *testing.T) {
	kp, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwtx.SignWithConfig(kp, &jwtx.SigningConfig{
		TTL: 5 * time.Minute,
	}, map[string]any{"sub": "user:alice"})
	if err != nil {
		t.Fatal(err)
	}

	sub, err := v.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if sub != "user:alice" {
		t.Fatalf("subject = %q, want user:alice", sub)
	}
}

func TestValidator_InvalidToken(t *testing.T) {
	_, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.ValidateToken("invalid.token.here")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidator_MissingSubjectClaim(t *testing.T) {
	kp, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwtx.Sign(kp, map[string]any{"email": "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error for missing sub claim")
	}
}

func TestUnaryInterceptor_WithToken(t *testing.T) {
	kp, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwtx.SignWithConfig(kp, &jwtx.SigningConfig{
		TTL: 5 * time.Minute,
	}, map[string]any{"sub": "user:bob"})
	if err != nil {
		t.Fatal(err)
	}

	interceptor := v.UnaryInterceptor()

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var capturedCtx context.Context
	handler := func(ctx context.Context, req any) (any, error) {
		capturedCtx = ctx
		return "ok", nil
	}

	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("resp = %v, want ok", resp)
	}

	sub, ok := SubjectFromContext(capturedCtx)
	if !ok || sub != "user:bob" {
		t.Fatalf("subject = %q, ok = %v, want user:bob", sub, ok)
	}
}

func TestUnaryInterceptor_NoToken(t *testing.T) {
	_, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	interceptor := v.UnaryInterceptor()

	handler := func(ctx context.Context, req any) (any, error) {
		_, ok := SubjectFromContext(ctx)
		if ok {
			t.Fatal("expected no subject in context when no token")
		}
		return "ok", nil
	}

	resp, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if resp != "ok" {
		t.Fatalf("resp = %v, want ok", resp)
	}
}

func TestUnaryInterceptor_InvalidToken(t *testing.T) {
	_, srv := testKeyAndServer(t)
	logger := slog.Default()

	v, err := NewValidator(&Config{
		JWKSURL:      srv.URL,
		SubjectClaim: "sub",
		CacheTTL:     5 * time.Minute,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}

	interceptor := v.UnaryInterceptor()

	md := metadata.Pairs("authorization", "Bearer bad.token.here")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}
