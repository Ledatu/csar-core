package gatewayctx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
)

func TestOriginAttributionPreservesServiceAndOwnedContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/report", nil)
	r.Header.Set(HeaderSubject, "reporting")
	service := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "reporting", EffectiveSubject: "reporting", CredentialKind: caller.STS, Assurance: caller.Verified}
	if err := SetCaller(r.Header, service); err != nil {
		t.Fatal(err)
	}
	origin := &Origin{Caller: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "key", Assurance: caller.Verified}, OperationID: uuid.NewString(), ParentOperationID: uuid.NewString(), ExpiresAt: time.Now().Add(time.Minute)}
	if err := SetOrigin(r.Header, origin); err != nil {
		t.Fatal(err)
	}
	id, err := FromRequestChecked(r)
	if err != nil || id.Subject != "reporting" || id.Caller.CallerID != "reporting" || id.Origin.Caller.CallerID != "agent" {
		t.Fatal("origin replaced hop identity", err)
	}
	ctx := NewContext(context.Background(), &id)
	id.Origin.Caller.CallerID = "changed"
	stored, _ := FromContext(ctx)
	if stored.Origin.Caller.CallerID != "agent" {
		t.Fatal("context alias")
	}
	stored.Origin.Caller.CallerID = "changed-again"
	stored, _ = FromContext(ctx)
	if stored.Origin.Caller.CallerID != "agent" {
		t.Fatal("getter alias")
	}
	for _, mutate := range []func(http.Header){
		func(h http.Header) { h.Add(HeaderOriginCaller, h.Get(HeaderOriginCaller)) },
		func(h http.Header) { h["x-gateway-operation-id"] = []string{uuid.NewString()} },
		func(h http.Header) { h.Del(HeaderOperationID) },
		func(h http.Header) { h.Set(HeaderOriginExpiresAt, "invalid") },
		func(h http.Header) { h.Set(HeaderParentOperationID, h.Get(HeaderOperationID)) },
	} {
		x := r.Clone(r.Context())
		mutate(x.Header)
		if _, err := FromRequestChecked(x); err == nil {
			t.Fatal("malformed origin accepted")
		}
	}
	StripTrusted(r.Header)
	if got, err := OriginFromHeaders(r.Header); err != nil || got != nil {
		t.Fatal("origin survived stripping", err)
	}
}
