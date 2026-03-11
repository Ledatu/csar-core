package gatewayctx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFromRequest_AllHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "req-123")
	r.Header.Set(HeaderSubject, "user-456")
	r.Header.Set(HeaderTenant, "tenant-789")
	r.Header.Set(HeaderRoles, "admin,editor")
	r.Header.Set(HeaderScopes, "read,write")
	r.Header.Set(HeaderAuthzResult, "allow")

	id := FromRequest(r)

	if id.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", id.RequestID, "req-123")
	}
	if id.Subject != "user-456" {
		t.Errorf("Subject = %q, want %q", id.Subject, "user-456")
	}
	if id.Tenant != "tenant-789" {
		t.Errorf("Tenant = %q, want %q", id.Tenant, "tenant-789")
	}
	if !reflect.DeepEqual(id.Roles, []string{"admin", "editor"}) {
		t.Errorf("Roles = %v, want [admin editor]", id.Roles)
	}
	if !reflect.DeepEqual(id.Scopes, []string{"read", "write"}) {
		t.Errorf("Scopes = %v, want [read write]", id.Scopes)
	}
	if id.AuthzResult != "allow" {
		t.Errorf("AuthzResult = %q, want %q", id.AuthzResult, "allow")
	}
}

func TestFromRequest_Empty(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	id := FromRequest(r)

	if id.RequestID != "" {
		t.Errorf("RequestID = %q, want empty", id.RequestID)
	}
	if id.Subject != "" {
		t.Errorf("Subject = %q, want empty", id.Subject)
	}
	if id.Roles != nil {
		t.Errorf("Roles = %v, want nil", id.Roles)
	}
	if id.Scopes != nil {
		t.Errorf("Scopes = %v, want nil", id.Scopes)
	}
}

func TestFromRequest_CSVSpaces(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRoles, " admin , editor , ")

	id := FromRequest(r)
	if !reflect.DeepEqual(id.Roles, []string{"admin", "editor"}) {
		t.Errorf("Roles = %v, want [admin editor]", id.Roles)
	}
}

func TestFromContext_Missing(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("expected ok=false for empty context")
	}
}

func TestNewContext_RoundTrip(t *testing.T) {
	id := Identity{
		RequestID: "req-1",
		Subject:   "user-2",
		Tenant:    "tenant-3",
		Roles:     []string{"viewer"},
	}
	ctx := NewContext(context.Background(), &id)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !reflect.DeepEqual(got, id) {
		t.Errorf("got %+v, want %+v", got, id)
	}
}

func TestMiddleware(t *testing.T) {
	var captured Identity
	var capturedOK bool

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, capturedOK = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := Middleware(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderRequestID, "mw-req")
	r.Header.Set(HeaderSubject, "mw-sub")
	r.Header.Set(HeaderRoles, "role1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if !capturedOK {
		t.Fatal("middleware did not set identity in context")
	}
	if captured.RequestID != "mw-req" {
		t.Errorf("RequestID = %q, want %q", captured.RequestID, "mw-req")
	}
	if captured.Subject != "mw-sub" {
		t.Errorf("Subject = %q, want %q", captured.Subject, "mw-sub")
	}
	if !reflect.DeepEqual(captured.Roles, []string{"role1"}) {
		t.Errorf("Roles = %v, want [role1]", captured.Roles)
	}
}

func TestTrustedMiddleware_Passes(t *testing.T) {
	alwaysTrust := func(r *http.Request) error { return nil }

	var captured Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = FromContext(r.Context())
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderSubject, "trusted-user")
	rec := httptest.NewRecorder()

	TrustedMiddleware(alwaysTrust)(inner).ServeHTTP(rec, r)

	if captured.Subject != "trusted-user" {
		t.Errorf("Subject = %q, want %q", captured.Subject, "trusted-user")
	}
}

func TestTrustedMiddleware_Rejects(t *testing.T) {
	neverTrust := func(r *http.Request) error {
		return fmt.Errorf("peer not verified")
	}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderSubject, "spoofed-user")
	rec := httptest.NewRecorder()

	TrustedMiddleware(neverTrust)(inner).ServeHTTP(rec, r)

	if called {
		t.Error("handler should not have been called for untrusted request")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestTrustedMiddleware_HeadersNotParsedOnReject(t *testing.T) {
	neverTrust := func(r *http.Request) error {
		return fmt.Errorf("nope")
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); ok {
			t.Error("identity should not be in context when trust check fails")
		}
	})

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderSubject, "spoofed")
	rec := httptest.NewRecorder()

	TrustedMiddleware(neverTrust)(inner).ServeHTTP(rec, r)
}

func TestSplitCSV_Edge(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{",,,", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ", []string{"a", "b"}},
	}
	for _, tt := range tests {
		got := splitCSV(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
