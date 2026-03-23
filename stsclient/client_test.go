package stsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/jwtx"
)

func TestTokenSource_Token_MockSTS(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		if r.FormValue("audience") != "test-aud" {
			http.Error(w, "bad aud", http.StatusBadRequest)
			return
		}
		assertion := r.FormValue("assertion")
		if assertion == "" || !strings.Contains(assertion, ".") {
			http.Error(w, "bad assertion", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "mock-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	ts, err := New(&Config{
		STSEndpoint:       srv.URL,
		Audience:          "test-aud",
		ServiceName:       "svc:test",
		AssertionAudience: "http://issuer",
		KeyPair:           kp,
		AssertionTTL:      0,
		HTTPClient:        srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "mock-access-token" {
		t.Fatalf("token = %q", tok)
	}

	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok {
		t.Fatalf("cache miss")
	}
}

func TestNew_ConfigValidation(t *testing.T) {
	kp, _ := jwtx.GenerateKeyPair("EdDSA")
	_, err := New(&Config{KeyPair: kp})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRefreshWindowForExpiresIn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, 0},
		{-1, 0},
		{10, 5 * time.Second},
		{60, 30 * time.Second},
		{61, 31 * time.Second},
		{3600, 3600*time.Second - tokenRefreshBuffer},
	}
	for _, tc := range cases {
		got := refreshWindowForExpiresIn(tc.in)
		if got != tc.want {
			t.Errorf("refreshWindowForExpiresIn(%d) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
