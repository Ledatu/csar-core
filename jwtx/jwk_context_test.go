package jwtx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteJWKSContextAndResponseBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = w.Write([]byte(strings.Repeat(" ", 65<<10)))
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	resolver := NewRemoteJWKS(server.URL)
	if _, err := resolver.KeyFuncContext(ctx)("kid", "EdDSA"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("JWKS fetch ignored operation cancellation", err)
	}
	if _, err := NewRemoteJWKS(server.URL+"/large").KeyFuncContext(t.Context())("kid", "EdDSA"); err == nil {
		t.Fatal("unbounded JWKS accepted")
	}
}
