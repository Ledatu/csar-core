package stsclient

import (
	"context"
	"fmt"
	"github.com/ledatu/csar-core/jwtx"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func redirectConfig(t *testing.T, issuer, router string) ServiceAuthConfig {
	t.Helper()
	kp, e := jwtx.GenerateKeyPair("EdDSA")
	if e != nil {
		t.Fatal(e)
	}
	priv, pub, e := jwtx.MarshalKeyPairPEM(kp)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	pr, pu := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
	if e = os.WriteFile(pr, priv, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(pu, pub, 0600); e != nil {
		t.Fatal(e)
	}
	return ServiceAuthConfig{RouterBaseURL: router, STSEndpoint: issuer, Audience: "fixture", ServiceName: "svc:fixture", AssertionAudience: "fixture", JWT: JWTKeysConfig{PrivateKeyFile: pr, PublicKeyFile: pu}}
}
func TestRouterClientNeverFollowsCredentialBearingRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var escaped atomic.Int32
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); _, _ = w.Write([]byte(`{}`)) }))
			defer sink.Close()
			issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"access_token":"synthetic-fixture-token","token_type":"Bearer","expires_in":3600}`))
			}))
			defer issuer.Close()
			router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Csar-Authorization") != "Bearer synthetic-fixture-token" {
					t.Error("missing router authentication")
				}
				http.Redirect(w, r, sink.URL+"/external", status)
			}))
			defer router.Close()
			cfg := redirectConfig(t, issuer.URL, router.URL)
			client, e := NewRouterClient(&cfg, nil)
			if e != nil {
				t.Fatal(e)
			}
			req, e := http.NewRequestWithContext(context.Background(), "POST", router.URL+"/read", strings.NewReader(`{}`))
			if e != nil {
				t.Fatal(e)
			}
			resp, e := client.Client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != status || escaped.Load() != 0 {
				t.Fatal("redirect escaped router boundary", resp.StatusCode, escaped.Load())
			}
		})
	}
}
func TestSTSRedirectCannotForwardSignedAssertion(t *testing.T) {
	var escaped atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1) }))
	defer sink.Close()
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/external", http.StatusTemporaryRedirect)
	}))
	defer issuer.Close()
	cfg := redirectConfig(t, issuer.URL, sink.URL)
	client, e := NewRouterClient(&cfg, nil)
	if e != nil {
		t.Fatal(e)
	}
	req, e := http.NewRequestWithContext(context.Background(), "GET", sink.URL+"/never", nil)
	if e != nil {
		t.Fatal(e)
	}
	resp, e := client.Client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if e == nil || escaped.Load() != 0 {
		t.Fatal("STS assertion escaped issuer boundary", escaped.Load())
	}
}
