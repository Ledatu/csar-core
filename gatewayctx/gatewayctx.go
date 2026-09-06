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

	"github.com/google/uuid"
)

// Trusted header names. The csar gateway strips client-supplied values
// for these headers and re-injects them from the validated token.
const (
	HeaderRequestID   = "X-Request-ID"
	HeaderSubject     = "X-Gateway-Subject"
	HeaderTenant      = "X-Gateway-Tenant"
	HeaderRoles       = "X-Gateway-Roles"        // comma-separated
	HeaderScopes      = "X-Gateway-Scopes"       // comma-separated
	HeaderAuthzResult = "X-Gateway-Authz-Result" // e.g. "allow", "deny"
	HeaderAuthzScope  = "X-Gateway-Authz-Scope"  // comma-separated scope types that granted access: "platform", "tenant"
	HeaderAuthzPolicy = "X-Gateway-Authz-Policy" // name of the route authz policy (branch) that granted access
)

// TrustedHeaders lists every identity header a backend may rely on. The
// gateway removes client-supplied values for all of them on every request
// before any validation step re-injects the ones it can vouch for.
var TrustedHeaders = []string{
	HeaderSubject,
	HeaderTenant,
	HeaderRoles,
	HeaderScopes,
	HeaderAuthzResult,
	HeaderAuthzScope,
	HeaderAuthzPolicy,
}

// StripTrusted removes every TrustedHeaders entry from h.
func StripTrusted(h http.Header) {
	for _, name := range TrustedHeaders {
		h.Del(name)
	}
}

// HeaderCsarAuthorization carries the service-to-service access token from a
// caller to the csar router. Note the direction is the opposite of the
// X-Gateway-* headers above: those are asserted by the gateway to a backend,
// this one is presented by a client to the gateway.
//
// It is deliberately not Authorization. The router proxies Authorization
// through to the upstream untouched on routes without a credential-injection
// profile, so the two must not share a header: a caller has to be able to
// authenticate the hop to csar and still pass its own upstream credential.
// The router strips this header before proxying.
const HeaderCsarAuthorization = "X-Csar-Authorization"

// Identity holds the request context forwarded by the gateway.
type Identity struct {
	RequestID   string
	Subject     string
	Tenant      string
	Roles       []string
	Scopes      []string
	AuthzResult string
	AuthzScopes []string
	AuthzPolicy string
}

// IsPlatformActor reports whether the authz decision was satisfied by a
// platform-scoped assignment, i.e. the caller acts as platform staff rather
// than as a member of the tenant the request targets.
func (id *Identity) IsPlatformActor() bool {
	for _, scope := range id.AuthzScopes {
		if scope == "platform" {
			return true
		}
	}
	return false
}

// SubjectUUID parses the Subject as a UUID. Returns an error if empty or invalid.
func (id *Identity) SubjectUUID() (uuid.UUID, error) {
	if id.Subject == "" {
		return uuid.Nil, fmt.Errorf("gatewayctx: empty subject")
	}
	return uuid.Parse(id.Subject)
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
		AuthzScopes: splitCSV(r.Header.Get(HeaderAuthzScope)),
		AuthzPolicy: r.Header.Get(HeaderAuthzPolicy),
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
