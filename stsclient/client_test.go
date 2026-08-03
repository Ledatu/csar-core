package stsclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
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

// TestBearerTransport_PreservesUpstreamAuthorization pins the header contract
// that service-to-service auth depends on: the STS token goes into
// X-Csar-Authorization, and a caller-supplied Authorization survives untouched.
//
// Regression guard. These used to be the same header, so a caller passing an
// upstream credential in Authorization had it silently overwritten by the STS
// token and the credential never left the process.
func TestBearerTransport_PreservesUpstreamAuthorization(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "sts-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer sts.Close()

	var gotCsarAuth, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCsarAuth = r.Header.Get(gatewayctx.HeaderCsarAuthorization)
		gotAuth = r.Header.Get("Authorization")
	}))
	defer upstream.Close()

	ts, err := New(&Config{
		STSEndpoint:       sts.URL,
		Audience:          "test-aud",
		ServiceName:       "svc:test",
		AssertionAudience: "http://issuer",
		KeyPair:           kp,
		HTTPClient:        sts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: ts.Transport(upstream.Client().Transport)}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer upstream-api-key")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if want := "Bearer sts-access-token"; gotCsarAuth != want {
		t.Errorf("%s = %q, want %q", gatewayctx.HeaderCsarAuthorization, gotCsarAuth, want)
	}
	if want := "Bearer upstream-api-key"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q — the caller credential must not be clobbered", gotAuth, want)
	}
}

// TestBearerTransport_DoesNotSetAuthorization ensures the STS token never lands
// in Authorization when the caller set no upstream credential, so a route that
// proxies Authorization verbatim cannot leak the internal token upstream.
func TestBearerTransport_DoesNotSetAuthorization(t *testing.T) {
	kp, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "sts-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer sts.Close()

	var gotAuth string
	var hadAuth bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, hadAuth = r.Header["Authorization"]
	}))
	defer upstream.Close()

	ts, err := New(&Config{
		STSEndpoint:       sts.URL,
		Audience:          "test-aud",
		ServiceName:       "svc:test",
		AssertionAudience: "http://issuer",
		KeyPair:           kp,
		HTTPClient:        sts.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: ts.Transport(upstream.Client().Transport)}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if hadAuth {
		t.Errorf("Authorization was set to %q, want absent — the STS token must not reach the upstream", gotAuth)
	}
}
