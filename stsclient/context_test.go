package stsclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/jwtx"
)

func TestTokenFailureDoesNotExposeIssuerBody(t *testing.T) {
	const diagnostic = "private assertion diagnostic"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, diagnostic, http.StatusForbidden)
	}))
	defer server.Close()
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	source, err := New(&Config{STSEndpoint: server.URL, Audience: "api", ServiceName: "svc:reporting", AssertionAudience: "issuer", KeyPair: keys, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Token(context.Background())
	if err == nil || strings.Contains(err.Error(), diagnostic) || !strings.Contains(err.Error(), "403") {
		t.Fatal("issuer body entered public error", err)
	}
}

func TestTokenWaiterCanCancelWithoutInterruptingRefresh(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "shared", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	source, err := New(&Config{STSEndpoint: server.URL, Audience: "api", ServiceName: "svc:reporting", AssertionAudience: "issuer", KeyPair: keys, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	leader := make(chan error, 1)
	go func() { _, err := source.Token(context.Background()); leader <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	follower := make(chan error, 1)
	go func() { _, err := source.Token(ctx); follower <- err }()
	select {
	case err := <-follower:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("waiter ignored deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter stuck behind another request's refresh")
	}
	close(release)
	if err := <-leader; err != nil {
		t.Fatal("waiter cancellation interrupted shared refresh", err)
	}
	if token, err := source.Token(context.Background()); err != nil || token != "shared" {
		t.Fatal("refreshed token cache lost", token, err)
	}
}
