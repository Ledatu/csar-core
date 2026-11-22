package origincontext

import (
	"context"
	"crypto"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/jwtx"
)

func TestSignedOriginBindingAndDelegationBounds(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_, _ string) (crypto.PublicKey, error) { return keys.PublicKey, nil }
	r := httptest.NewRequest(http.MethodPost, "/svc/report?store=a", strings.NewReader(`{"days":7}`))
	hash, err := RequestHash(r)
	if err != nil {
		t.Fatal(err)
	}
	in := &RootRequest{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent:1", OwnerSubject: "user:1", EffectiveSubject: "user:1", CredentialKind: caller.APIKey, CredentialID: "key:1", Assurance: caller.Verified},
		Receiver: "reporting", Resource: "tenant:1", RequestHash: hash, SourceExpiresAt: time.Now().Add(30 * time.Second)}
	root, err := IssueRoot(keys, "issuer", in)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := Verify(root.Token, lookup, "issuer", "reporting")
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithVerifiedProof(context.Background(), &Proof{Token: root.Token, Claims: parent})
	ownedProof, ok := ProofFromContext(ctx)
	if !ok || ownedProof.Token != root.Token {
		t.Fatal("verified proof lost")
	}
	ownedProof.Claims.Origin.CallerID = "changed"
	storedProof, _ := ProofFromContext(ctx)
	if storedProof.Claims.Origin.CallerID != "agent:1" {
		t.Fatal("proof context aliased")
	}
	if _, ok := ProofFromContext(WithVerified(ctx, parent)); ok {
		t.Fatal("metadata replacement retained another proof")
	}
	cleared := WithVerifiedProof(ctx, nil)
	if _, ok := ProofFromContext(cleared); ok {
		t.Fatal("nil proof retained credential")
	}
	if _, ok := FromContext(cleared); ok {
		t.Fatal("nil proof retained claims")
	}
	if !parent.ExpiresAt.Before(in.SourceExpiresAt.Add(time.Nanosecond)) || parent.CheckHop("reporting", "tenant:1", hash) == nil {
		t.Fatal("root used as service hop or source expiry extended")
	}
	proof := root
	for range MaxDepth {
		proof, err = Delegate(keys, "issuer", "reporting", &DelegateRequest{ParentToken: proof.Token, Receiver: "reporting", Resource: "tenant:1", RequestHash: hash})
		if err != nil {
			t.Fatal(err)
		}
		c, err := Verify(proof.Token, lookup, "issuer", "reporting")
		if err != nil {
			t.Fatal(err)
		}
		if !c.ExpiresAt.Equal(root.ExpiresAt) || c.Origin.CallerID != "agent:1" || c.CheckHop("reporting", "tenant:1", hash) != nil {
			t.Fatal("delegation changed origin, expiry or binding")
		}
		if c.CheckHop("foreign", "tenant:1", hash) == nil || c.CheckHop("reporting", "foreign", hash) == nil || c.CheckHop("reporting", "tenant:1", strings.Repeat("0", 64)) == nil {
			t.Fatal("foreign binding accepted")
		}
		ctx := WithVerified(context.Background(), c)
		c.Origin.CallerID = "mutated"
		c.ExpiresAt.Time = c.ExpiresAt.Add(time.Hour)
		owned, _ := FromContext(ctx)
		if owned.Origin.CallerID != "agent:1" || !owned.ExpiresAt.Equal(root.ExpiresAt) {
			t.Fatal("context aliased")
		}
	}
	if _, err := Delegate(keys, "issuer", "reporting", &DelegateRequest{ParentToken: proof.Token, Receiver: "reporting", Resource: "tenant:1", RequestHash: hash}); err == nil {
		t.Fatal("unbounded depth")
	}
	for _, test := range []struct{ issuer, receiver, token string }{{"foreign", "reporting", root.Token}, {"issuer", "foreign", root.Token}, {"issuer", "reporting", root.Token + "x"}, {"issuer", "reporting", strings.Repeat("x", MaxTokenBytes+1)}} {
		if _, err := Verify(test.token, lookup, test.issuer, test.receiver); err == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	if _, err := Delegate(keys, "issuer", "foreign", &DelegateRequest{ParentToken: root.Token, Receiver: "reporting", Resource: "tenant:1", RequestHash: hash}); err == nil {
		t.Fatal("wrong service delegated")
	}
	in.SourceExpiresAt = time.Now().Add(-time.Second)
	if _, err := IssueRoot(keys, "issuer", in); err == nil {
		t.Fatal("expired source minted context")
	}
	in.SourceExpiresAt = time.Now().Add(time.Minute)
	in.Resource = ""
	if _, err := IssueRoot(keys, "issuer", in); err == nil {
		t.Fatal("unbound resource accepted")
	}
}

func TestRequestHashPreservesBodyAndOriginalTarget(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/svc/report?store=a", strings.NewReader(`{"days":7}`))
	r.Header.Set("Content-Type", "application/json")
	before, err := RequestHash(r)
	if err != nil {
		t.Fatal(err)
	}
	r.URL.Path = "/rewritten"
	after, err := RequestHash(r)
	if err != nil || after != before {
		t.Fatal("route rewrite broke original target binding", err)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || string(body) != `{"days":7}` {
		t.Fatal("body was consumed", err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Method = http.MethodGet }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, func(r *http.Request) { r.RequestURI = "/svc/report?store=foreign" }} {
		x := httptest.NewRequest(http.MethodPost, "/svc/report?store=a", strings.NewReader(`{"days":7}`))
		x.Header.Set("Content-Type", "application/json")
		change(x)
		h, err := RequestHash(x)
		if err != nil || h == before {
			t.Fatal("different request had same binding", err)
		}
	}
	x := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", MaxBodyBytes+1)))
	if _, err := RequestHash(x); err == nil {
		t.Fatal("unbounded body accepted")
	}
	x = httptest.NewRequest(http.MethodGet, "/", nil)
	x.Header["Content-Type"] = []string{"application/json"}
	x.Header["content-type"] = []string{"text/plain"}
	if _, err := RequestHash(x); err == nil {
		t.Fatal("ambiguous interpretation accepted")
	}
	x = httptest.NewRequest(http.MethodPost, "/svc/report?store=a", strings.NewReader(`{"days":7}`))
	x.Header["content-type"] = []string{"application/json"}
	if h, err := RequestHash(x); err != nil || h != before {
		t.Fatal("header casing changed request digest", err)
	}
}
