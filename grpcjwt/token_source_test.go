package grpcjwt

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/jwtx"
)

func TestServiceTokenSource_MintsToken(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	src := NewServiceTokenSource(kp, "svc:test", &jwtx.SigningConfig{
		Issuer:   "test-issuer",
		Audience: []string{"csar-authz"},
		TTL:      5 * time.Minute,
	})

	md, err := src.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	auth, ok := md["authorization"]
	if !ok {
		t.Fatal("missing authorization key")
	}
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("expected Bearer prefix, got %q", auth)
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	sub, err := jwtx.Verify(token, func(_, _ string) (crypto.PublicKey, error) {
		return kp.PublicKey, nil
	}, &jwtx.VerifyConfig{
		RequiredIssuer:   "test-issuer",
		RequiredAudience: "csar-authz",
	})
	if err != nil {
		t.Fatalf("token validation failed: %v", err)
	}
	if sub.Claims["sub"] != "svc:test" {
		t.Errorf("subject = %q, want %q", sub.Claims["sub"], "svc:test")
	}
}

func TestServiceTokenSource_CachesToken(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	src := NewServiceTokenSource(kp, "svc:cache-test", &jwtx.SigningConfig{
		Issuer:   "test",
		Audience: []string{"test"},
		TTL:      5 * time.Minute,
	})

	md1, _ := src.GetRequestMetadata(context.Background())
	md2, _ := src.GetRequestMetadata(context.Background())

	if md1["authorization"] != md2["authorization"] {
		t.Error("expected same cached token on second call")
	}
}

func TestServiceTokenSource_RequiresTransportSecurity(t *testing.T) {
	src := &ServiceTokenSource{}
	if !src.RequireTransportSecurity() {
		t.Error("expected RequireTransportSecurity to be true")
	}
}
