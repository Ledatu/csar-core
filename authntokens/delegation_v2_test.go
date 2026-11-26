package authntokens

import (
	"github.com/ledatu/csar-core/caller"
	"testing"
	"time"
)

func TestV2DelegationBindingsCannotDowngrade(t *testing.T) {
	now := time.Now()
	ref := ResourceRef{Namespace: "workspace", ID: "north-branch"}
	req := DelegationRequestV2{Version: 2, Token: "opaque", Purpose: GrantResource, ProfileID: "reports", Audience: "https://reports.test", Scope: "reports:read", Namespace: ref.Namespace, Resource: &ref}
	id := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialID: "grant", CredentialKind: caller.DelegationProof, Assurance: caller.Verified}
	out := DelegationResultV2{Version: 2, Active: true, Purpose: req.Purpose, ProfileID: req.ProfileID, ProfileRevision: 1, Audience: req.Audience, Scope: req.Scope, Namespace: req.Namespace, Resource: &ref, AuthorizedScope: &ScopeRef{Type: "tenant", ID: "workspace:north-branch"}, Identity: id, ExpiresAt: now.Add(time.Minute)}
	if err := out.ValidateFor(&req, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*DelegationResultV2){func(o *DelegationResultV2) { o.Version = 1 }, func(o *DelegationResultV2) { o.ProfileRevision = 0 }, func(o *DelegationResultV2) { o.ProfileID = "other" }, func(o *DelegationResultV2) { o.Namespace = "other" }, func(o *DelegationResultV2) { o.Resource = &ResourceRef{Namespace: "other", ID: ref.ID} }, func(o *DelegationResultV2) { o.AuthorizedScope = nil }, func(o *DelegationResultV2) { o.ExpiresAt = now }, func(o *DelegationResultV2) { o.DelegatedToken = "unexpected" }} {
		bad := out
		mutate(&bad)
		if bad.ValidateFor(&req, now) == nil {
			t.Fatal("v2 authority substitution accepted")
		}
	}
	req.Version = 1
	if req.Validate() == nil {
		t.Fatal("v1 accepted")
	}
	if IsDelegation(GrantResourceV2) || IsDelegationV2(GrantResource) {
		t.Fatal("modes silently alias")
	}
}
