package origincontext

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/jwtx"
)

func rootTestClient(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected test transport")
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}
	return server, client
}

func TestRootClientMTLSBindingsAndFailureBounds(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_, _ string) (crypto.PublicKey, error) { return keys.PublicKey, nil }
	var mode atomic.Int32
	var calls atomic.Int32
	server, httpClient := rootTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/root" || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("root ingress changed or carried other credentials")
		}
		var request RootRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		switch mode.Load() {
		case 1:
			request.Resource = "foreign"
		case 2:
			http.Redirect(w, r, serverURLForTest(r)+"/redirect", http.StatusTemporaryRedirect)
			return
		case 3:
			_, _ = w.Write([]byte(strings.Repeat("x", 17<<10)))
			return
		case 4:
			http.Error(w, "private-issuer-diagnostic", http.StatusServiceUnavailable)
			return
		case 5:
			<-r.Context().Done()
			return
		case 6:
			request.Caller.CallerID = "foreign"
		case 7:
			request.RequestHash = strings.Repeat("b", 64)
		case 8:
			request.SourceExpiresAt = time.Now().Add(time.Hour)
		}
		response, err := IssueRoot(keys, "issuer", &request)
		if err != nil {
			t.Error(err)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Error(err)
		}
	}))
	client, err := NewRootClient(RootClientConfig{Endpoint: server.URL + "/root", Issuer: "issuer", HTTPClient: httpClient, KeyFunc: lookup})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	request := &RootRequest{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}, Receiver: "reporting", Resource: "tenant", RequestHash: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(30 * time.Second)}
	proof, err := client.Issue(t.Context(), request)
	if err != nil || proof.Claims.Origin.CallerID != "agent" || proof.Claims.Depth != 0 {
		t.Fatal("root issuance failed", err)
	}
	for _, m := range []int32{1, 2, 3, 4, 6, 7, 8} {
		mode.Store(m)
		before := calls.Load()
		if _, err := client.Issue(t.Context(), request); err == nil || strings.Contains(err.Error(), "private-issuer-diagnostic") {
			t.Fatal("invalid response accepted or diagnostics exposed", m, err)
		}
		if calls.Load() != before+1 {
			t.Fatal("root was retried or redirected")
		}
	}
	mode.Store(5)
	mode.Store(0)
	contextClient, err := NewRootClient(RootClientConfig{Endpoint: server.URL + "/root", Issuer: "issuer", HTTPClient: httpClient, KeyFuncContext: func(ctx context.Context) jwtx.KeyFunc {
		return func(_, _ string) (crypto.PublicKey, error) { <-ctx.Done(); return nil, ctx.Err() }
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer contextClient.Close()
	lookupCtx, lookupCancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer lookupCancel()
	if _, err := contextClient.Issue(lookupCtx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("signature lookup ignored operation deadline", err)
	}
	mode.Store(5)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Issue(ctx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("request cancellation lost", err)
	}
	for _, endpoint := range []string{"http://issuer/root", server.URL + "/root?secret=x", server.URL + "/root#fragment", server.URL + "/../root", server.URL + "/root%2fother"} {
		if c, err := NewRootClient(RootClientConfig{Endpoint: endpoint, Issuer: "issuer", HTTPClient: httpClient, KeyFunc: lookup}); err == nil {
			c.Close()
			t.Fatal("unsafe endpoint accepted")
		}
	}
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if _, err := NewRootClient(RootClientConfig{Endpoint: server.URL + "/root", Issuer: "issuer", HTTPClient: plain, KeyFunc: lookup}); err == nil {
		t.Fatal("missing mTLS capability accepted")
	}
}

func serverURLForTest(r *http.Request) string { return "https://" + r.Host }
