package origincontext

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/stsclient"
)

func TestDelegationUsesPerRequestProofAndSharedSTS(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_, _ string) (crypto.PublicKey, error) { return keys.PublicKey, nil }
	var exchanges, delegations, reads atomic.Int32
	var fail atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sts" {
			exchanges.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if strings.Contains(r.Form.Get("assertion"), "parent_token") {
				t.Error("parent entered STS exchange")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": r.Form.Get("audience") + "-sts", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		expected := "access-sts"
		if r.URL.Path == "/svc/authn/origin-context/delegate" {
			expected = "delegate-sts"
		}
		if r.Header.Get(gatewayctx.HeaderCsarAuthorization) != "Bearer "+expected {
			t.Error("missing immediate service STS")
		}
		if r.URL.Path == "/svc/authn/origin-context/delegate" {
			delegations.Add(1)
			var in DelegateRequest
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Error(err)
			}
			if fail.Load() {
				http.Error(w, "private issuer error", http.StatusServiceUnavailable)
				return
			}
			result, err := Delegate(keys, "issuer", "svc:reporting", &in)
			if err != nil {
				http.Error(w, "invalid parent", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(result)
			return
		}
		reads.Add(1)
		if r.Header.Get(HeaderForwardedAuthorization) != "" {
			t.Error("raw parent forwarded to downstream")
		}
		child, err := Verify(strings.TrimPrefix(r.Header.Get(HeaderAuthorization), "Bearer "), lookup, "issuer", "svc:owner")
		hash, hashErr := RequestHash(r)
		if err != nil || hashErr != nil || child.CheckHop("svc:reporting", "wildberries:cabinet", hash) != nil {
			t.Error("child not bound to actual request", err)
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"caller": child.Origin.CallerID})
	}))
	defer server.Close()
	ts, err := stsclient.New(&stsclient.Config{STSEndpoint: server.URL + "/sts", Audience: "access", ServiceName: "svc:reporting", AssertionAudience: "issuer", KeyPair: keys, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	authenticated := *server.Client()
	authenticated.Transport = ts.Transport(authenticated.Transport)
	issuerTS, err := stsclient.New(&stsclient.Config{STSEndpoint: server.URL + "/sts", Audience: "delegate", ServiceName: "svc:reporting", AssertionAudience: "issuer", KeyPair: keys, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	issuerAuthenticated := *server.Client()
	issuerAuthenticated.Transport = issuerTS.Transport(issuerAuthenticated.Transport)
	delegate, err := NewDelegateClient(server.URL, &authenticated, &issuerAuthenticated)
	if err != nil {
		t.Fatal(err)
	}
	client, err := delegate.Client("svc:owner")
	if err != nil {
		t.Fatal(err)
	}
	parentContext := func(name string) context.Context {
		t.Helper()
		original := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: name, OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, Assurance: caller.Verified}
		root, err := IssueRoot(keys, "issuer", &RootRequest{Caller: original, Receiver: "svc:reporting", Resource: "wildberries:cabinet", RequestHash: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := Verify(root.Token, lookup, "issuer", "svc:reporting")
		if err != nil {
			t.Fatal(err)
		}
		incoming := httptest.NewRequest("GET", "/report", nil)
		incoming.Header.Set(gatewayctx.HeaderTenant, "wildberries:cabinet")
		if err := gatewayctx.SetOrigin(incoming.Header, &gatewayctx.Origin{Caller: original, OperationID: claims.OperationID, ExpiresAt: root.ExpiresAt}); err != nil {
			t.Fatal(err)
		}
		incoming.Header.Set(HeaderForwardedAuthorization, "Bearer "+root.Token)
		ctx, err := WithGatewayParent(context.Background(), incoming)
		if err != nil {
			t.Fatal(err)
		}
		return ctx
	}
	for _, name := range []string{"agent-one", "agent-two"} {
		req, err := http.NewRequestWithContext(parentContext(name), "POST", server.URL+"/read?period=7", strings.NewReader(`{"metrics":["orders"]}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || !strings.Contains(string(body), name) {
			t.Fatal("origin lost", string(body), err)
		}
	}
	if exchanges.Load() != 2 || delegations.Load() != 2 || reads.Load() != 2 {
		t.Fatal("origin polluted STS cache or reused child")
	}
	req, _ := http.NewRequest("GET", server.URL+"/read", nil)
	if _, err := client.Do(req); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing parent accepted", err)
	}
	req, _ = http.NewRequestWithContext(parentContext("agent"), "GET", "https://other.invalid/read", nil)
	if _, err := client.Do(req); !errors.Is(err, ErrInvalid) {
		t.Fatal("proof could leak off router", err)
	}
	fail.Store(true)
	req, _ = http.NewRequestWithContext(parentContext("agent"), "GET", server.URL+"/read", nil)
	req.Host = "other.invalid"
	if _, err := client.Do(req); !errors.Is(err, ErrInvalid) {
		t.Fatal("HTTP Host bypassed router binding", err)
	}
	req, _ = http.NewRequestWithContext(parentContext("agent"), "GET", server.URL+"/read", nil)
	if _, err := client.Do(req); !errors.Is(err, ErrIssuerUnavailable) || strings.Contains(err.Error(), "private issuer") {
		t.Fatal("issuer failure not bounded/redacted", err)
	}
	if reads.Load() != 2 || delegations.Load() != 3 {
		t.Fatal("issuer failure dispatched/retried")
	}
}

func TestDelegatedResponseHonorsShorterChildExpiry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/svc/authn/origin-context/delegate" {
			_ = json.NewEncoder(w).Encode(Response{Token: "opaque-child", ExpiresAt: time.Now().Add(150 * time.Millisecond)})
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	delegate, err := NewDelegateClient(server.URL, server.Client(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := delegate.Client("svc:owner")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, gatewayParentKey{}, gatewayParent{token: "parent", resource: "wildberries:cabinet", expires: time.Now().Add(time.Minute)})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/read", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := client.Do(req)
	if err == nil {
		_, err = io.ReadAll(response.Body)
		_ = response.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("response outlived child proof", err)
	}
}

func TestGatewayParentRejectsPartialDuplicateAndExpired(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if _, err := WithGatewayParent(context.Background(), req); err == nil {
		t.Fatal("missing parent accepted")
	}
	original := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: "user", OwnerSubject: "user", EffectiveSubject: "user", CredentialKind: caller.Session, Assurance: caller.Verified}
	if err := gatewayctx.SetOrigin(req.Header, &gatewayctx.Origin{Caller: original, OperationID: "b443af11-1ca2-4cbe-8858-1f46d29f1ee1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	req.Header.Set(gatewayctx.HeaderTenant, "wildberries:cabinet")
	req.Header[HeaderForwardedAuthorization] = []string{"Bearer parent", "Bearer another"}
	if _, err := WithGatewayParent(context.Background(), req); err == nil {
		t.Fatal("duplicate parent accepted")
	}
	req.Header[HeaderForwardedAuthorization] = []string{"Bearer parent"}
	req.Header.Set(gatewayctx.HeaderOriginExpiresAt, time.Now().Add(-time.Second).Format(time.RFC3339Nano))
	if _, err := WithGatewayParent(context.Background(), req); err == nil {
		t.Fatal("expired parent accepted")
	}
}
