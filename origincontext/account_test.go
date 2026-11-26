package origincontext

import (
	"crypto"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAccountOriginPreservesBindingWithoutTenant(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_, _ string) (crypto.PublicKey, error) { return keys.PublicKey, nil }
	for _, human := range []bool{false, true} {
		id := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "grant", Assurance: caller.Verified}
		binding := &authntokens.AccountBinding{Kind: "credential", ProfileID: "reports", ProfileRevision: math.MaxUint64, Audience: "https://reports.example.test"}
		if human {
			id.CallerKind = caller.Human
			id.CallerID = "owner"
			id.CredentialKind = caller.Session
			id.CredentialID = ""
			binding = &authntokens.AccountBinding{Kind: "subject"}
		}
		in := &RootRequest{Caller: id, Account: binding, Receiver: "svc:campaigns", RequestHash: strings.Repeat("a", 64), SourceExpiresAt: time.Now().Add(30 * time.Second)}
		root, err := IssueRoot(keys, "issuer", in)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := Verify(root.Token, lookup, "issuer", "svc:campaigns")
		if err != nil || claims.Version != 2 || claims.Resource != "" || *claims.Account != *binding {
			t.Fatal("account root lost binding", err)
		}
		request := &DelegateRequest{Account: binding, ParentToken: root.Token, Receiver: "svc:authn", RequestHash: strings.Repeat("b", 64)}
		child, err := Delegate(keys, "issuer", "svc:campaigns", request)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Verify(child.Token, lookup, "issuer", "svc:authn")
		if err != nil || !c.ExpiresAt.Equal(root.ExpiresAt) || c.CheckHop("svc:campaigns", "", request.RequestHash) != nil {
			t.Fatal("account hop changed authority", err)
		}
		bad := *request
		bad.Account = nil
		if _, err := Delegate(keys, "issuer", "svc:campaigns", &bad); err == nil {
			t.Fatal("account downgraded to tenant")
		}
		bad = *request
		bad.Resource = "tenant:fake"
		if _, err := Delegate(keys, "issuer", "svc:campaigns", &bad); err == nil {
			t.Fatal("account acquired tenant")
		}
		ctx := WithVerifiedProof(t.Context(), &Proof{Token: root.Token, Claims: claims})
		owned, _ := ProofFromContext(ctx)
		owned.Claims.Account.Kind = "mutated"
		again, _ := ProofFromContext(ctx)
		if again.Claims.Account.Kind != binding.Kind {
			t.Fatal("account context aliases input")
		}
		r := httptest.NewRequest("GET", "/discovery", nil)
		if err := gatewayctx.SetOrigin(r.Header, &gatewayctx.Origin{Caller: id, Account: binding, OperationID: claims.OperationID, ExpiresAt: claims.ExpiresAt.Time}); err != nil {
			t.Fatal(err)
		}
		r.Header.Set(HeaderForwardedAuthorization, "Bearer "+root.Token)
		if _, err := WithGatewayAccountParent(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if _, err := WithGatewayParent(t.Context(), r); err == nil {
			t.Fatal("tenant helper accepted account")
		}
		r.Header.Set(gatewayctx.HeaderTenant, "tenant:fake")
		if _, err := WithGatewayAccountParent(t.Context(), r); err == nil {
			t.Fatal("account helper imported tenant")
		}
		in.Resource = "tenant:fake"
		if _, err := IssueRoot(keys, "issuer", in); err == nil {
			t.Fatal("account root acquired tenant")
		}
	}
}
