// Package gatewayctx parses trusted identity headers injected by the
// csar gateway. Internal services read the subject, tenant, roles,
// scopes, request ID, and authz decision from these headers rather
// than re-implementing token validation.
//
// IMPORTANT: This package is a header parser, NOT a trust enforcement
// mechanism. Parsing headers alone does not prove they were set by a
// trusted gateway. Without an independent trust signal — such as mTLS
// peer verification or a signed context token — any direct caller can
// spoof these headers.
//
// For production use, combine this package with one of:
//   - mTLS (via tlsx) that restricts ingress to the gateway's client cert
//   - A TrustFunc passed to TrustedMiddleware that verifies the request
//     source before the headers are accepted
//   - Network-level isolation that prevents untrusted traffic from
//     reaching the service
package gatewayctx

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Trusted header names. The csar gateway strips client-supplied values
// for these headers and re-injects them from the validated token.
const (
	HeaderRequestID   = "X-Request-ID"
	HeaderSubject     = "X-Gateway-Subject"
	HeaderTenant      = "X-Gateway-Tenant"
	HeaderRoles       = "X-Gateway-Roles"       // comma-separated
	HeaderScopes      = "X-Gateway-Scopes"      // comma-separated
	HeaderAuthzResult = "X-Gateway-Authz-Result" // e.g. "allow", "deny"
)

// Identity holds the request context forwarded by the gateway.
type Identity struct {
	RequestID   string
	Subject     string
	Tenant      string
	Roles       []string
	Scopes      []string
	AuthzResult string
}

type ctxKey struct{}

// FromRequest extracts an Identity from HTTP request headers.
// This is a pure parser — it does not verify the request source.
func FromRequest(r *http.Request) Identity {
	return Identity{
		RequestID:   r.Header.Get(HeaderRequestID),
		Subject:     r.Header.Get(HeaderSubject),
		Tenant:      r.Header.Get(HeaderTenant),
		Roles:       splitCSV(r.Header.Get(HeaderRoles)),
		Scopes:      splitCSV(r.Header.Get(HeaderScopes)),
		AuthzResult: r.Header.Get(HeaderAuthzResult),
	}
}

// FromContext retrieves the Identity stored by Middleware or TrustedMiddleware.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// NewContext returns a new context carrying the given Identity.
func NewContext(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, *id)
}

// Middleware parses gateway headers and stores the resulting Identity
// in the request context. It does NOT verify the request source.
// Use TrustedMiddleware when you need trust enforcement.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromRequest(r)
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), &id)))
	})
}

// TrustFunc inspects a request and returns nil if the request
// originates from a trusted source (e.g. the gateway). A non-nil
// error means the request should be rejected.
type TrustFunc func(r *http.Request) error

// TrustedMiddleware parses gateway headers only after the TrustFunc
// confirms the request source is legitimate. If trust verification
// fails the request is rejected with 403 Forbidden and the gateway
// headers are NOT parsed into the context.
func TrustedMiddleware(verify TrustFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := verify(r); err != nil {
				http.Error(w, fmt.Sprintf("untrusted request: %v", err), http.StatusForbidden)
				return
			}
			id := FromRequest(r)
			next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), &id)))
		})
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
