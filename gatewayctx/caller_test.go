package gatewayctx

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/caller"
)

func boundCallerRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderSubject, "user:1")
	r.Header.Set(HeaderCredentialID, "key:1")
	id := &caller.Identity{Version: caller.Version, CallerKind: caller.Agent, CallerID: "agent:1", OwnerSubject: "user:1",
		EffectiveSubject: "user:1", CredentialKind: caller.APIKey, CredentialID: "key:1", Assurance: caller.Verified}
	if err := SetCaller(r.Header, id); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCallerContextRoundTripAndOwnership(t *testing.T) {
	r := boundCallerRequest(t)
	called := false
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		id, ok := FromContext(r.Context())
		if !ok || id.Caller == nil || id.Caller.CallerID != "agent:1" || id.Caller.CredentialID != id.CredentialID {
			t.Fatal("trusted caller not parsed")
		}
		id.Caller.CallerID = "mutated"
		again, _ := FromContext(r.Context())
		if again.Caller.CallerID != "agent:1" {
			t.Fatal("caller aliased context on read")
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("valid caller rejected")
	}
	id := FromRequest(r)
	ctx := NewContext(context.Background(), &id)
	id.Caller.CallerID = "mutated"
	stored, _ := FromContext(ctx)
	if stored.Caller.CallerID != "agent:1" {
		t.Fatal("caller aliased context on write")
	}
	if err := SetCaller(r.Header, nil); err != nil {
		t.Fatal(err)
	}
	legacy, err := FromRequestChecked(r)
	if err != nil || legacy.Caller != nil || legacy.Subject != "user:1" {
		t.Fatal("legacy request changed", err)
	}
}

func TestCallerHeaderRejectsMalformedOrMismatchedAssertions(t *testing.T) {
	for name, mutate := range map[string]func(http.Header){
		"subject":              func(h http.Header) { h.Set(HeaderSubject, "foreign") },
		"credential":           func(h http.Header) { h.Set(HeaderCredentialID, "foreign") },
		"duplicate":            func(h http.Header) { h.Add(HeaderCaller, h.Get(HeaderCaller)) },
		"duplicate subject":    func(h http.Header) { h.Add(HeaderSubject, h.Get(HeaderSubject)) },
		"duplicate credential": func(h http.Header) { h.Add(HeaderCredentialID, h.Get(HeaderCredentialID)) },
		"raw subject casing":   func(h http.Header) { h["x-gateway-subject"] = []string{h.Get(HeaderSubject)} },
		"raw casing duplicate": func(h http.Header) { h["x-gateway-caller"] = []string{h.Get(HeaderCaller)} },
		"empty":                func(h http.Header) { h.Set(HeaderCaller, "") },
		"oversize":             func(h http.Header) { h.Set(HeaderCaller, strings.Repeat("x", MaxCallerHeaderBytes+1)) },
		"encoding":             func(h http.Header) { h.Set(HeaderCaller, "Bearer secret") },
		"version": func(h http.Header) {
			h.Set(HeaderCaller, base64.RawURLEncoding.EncodeToString([]byte(`{"version":2}`)))
		},
		"unknown field": func(h http.Header) {
			h.Set(HeaderCaller, base64.RawURLEncoding.EncodeToString([]byte(`{"untrusted":"secret"}`)))
		},
		"trailing document": func(h http.Header) {
			b, err := base64.RawURLEncoding.DecodeString(h.Get(HeaderCaller))
			if err != nil {
				t.Fatal(err)
			}
			h.Set(HeaderCaller, base64.RawURLEncoding.EncodeToString(append(b, []byte(` {}`)...)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := boundCallerRequest(t)
			mutate(r.Header)
			if id := FromRequest(r); id.Subject != "" || id.Caller != nil {
				t.Fatal("compatibility parser downgraded malformed metadata to an authenticated identity")
			}
			w := httptest.NewRecorder()
			Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("malformed caller reached backend") })).ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "secret") {
				t.Fatal("malformed metadata accepted or echoed", w.Code)
			}
		})
	}
}

func TestReservedGatewayNamespaceCannotSurviveStripping(t *testing.T) {
	h := http.Header{"x-gateway-future-identity": {"forged"}, "X-GATEWAY-ORIGIN-CALLER": {"forged"}, "Authorization": {"Bearer retained"}}
	h.Set(HeaderRequestID, "request:1")
	h.Set(HeaderCaller, "forged")
	StripTrusted(h)
	if len(h) != 2 || h.Get("Authorization") != "Bearer retained" || h.Get(HeaderRequestID) != "request:1" {
		t.Fatal("reserved namespace survived or caller credentials changed")
	}
	r := boundCallerRequest(t)
	id := FromRequest(r).Caller
	id.CredentialID = "foreign"
	if SetCaller(r.Header, id) == nil || r.Header.Get(HeaderCaller) != "" {
		t.Fatal("invalid replacement retained a caller assertion")
	}
}
