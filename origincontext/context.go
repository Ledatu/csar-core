// Package origincontext implements short-lived attribution proofs. They grant
// no access: CSAR must separately authenticate and authorize the service hop.
package origincontext

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/jwtx"
)

const (
	TokenUse                     = "csar_origin_context_v1"
	AudiencePrefix               = "urn:csar:origin:"
	HeaderAuthorization          = "X-Csar-Origin-Authorization"
	HeaderForwardedAuthorization = "X-Gateway-Origin-Authorization"
	MaxLifetime                  = time.Minute
	MaxDepth                     = 4
	MaxTokenBytes                = 8192
)

var ErrInvalid = errors.New("origincontext: invalid attribution proof")

type RootRequest struct {
	Caller          *caller.Identity `json:"caller"`
	Receiver        string           `json:"receiver"`
	Resource        string           `json:"resource"`
	RequestHash     string           `json:"request_hash"`
	SourceExpiresAt time.Time        `json:"source_expires_at"`
}

type DelegateRequest struct {
	ParentToken string `json:"parent_token"`
	Receiver    string `json:"receiver"`
	Resource    string `json:"resource"`
	RequestHash string `json:"request_hash"`
}

type Response struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Claims struct {
	Version           int              `json:"version"`
	TokenUse          string           `json:"token_use"`
	Origin            *caller.Identity `json:"origin"`
	Receiver          string           `json:"receiver"`
	Sender            string           `json:"sender,omitempty"`
	Resource          string           `json:"resource"`
	RequestHash       string           `json:"request_hash"`
	OperationID       string           `json:"operation_id"`
	ParentOperationID string           `json:"parent_operation_id,omitempty"`
	Depth             int              `json:"depth"`
	jwt.RegisteredClaims
}

// IssueRoot accepts only a principal already verified by the trusted gateway.
// An HTTP adapter must enforce that boundary before accepting RootRequest.
func IssueRoot(keys *jwtx.KeyPair, issuer string, in *RootRequest) (*Response, error) {
	if in == nil || in.Caller.Validate() != nil {
		return nil, ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(MaxLifetime)
	if in.SourceExpiresAt.Before(deadline) {
		deadline = in.SourceExpiresAt.UTC().Truncate(time.Second)
	}
	original := *in.Caller
	c := &Claims{Version: 1, TokenUse: TokenUse, Origin: &original, Receiver: in.Receiver, Resource: in.Resource, RequestHash: in.RequestHash,
		OperationID: uuid.NewString(), RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{AudiencePrefix + in.Receiver},
			ID: uuid.NewString(), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(deadline)}}
	return sign(keys, c)
}

// Delegate requires a parent addressed to the separately authenticated service.
// It preserves resource, original principal and expiry; it never refreshes a grant.
func Delegate(keys *jwtx.KeyPair, issuer, service string, in *DelegateRequest) (*Response, error) {
	if keys == nil || in == nil || service == "" || !caller.ValidReference(service) {
		return nil, ErrInvalid
	}
	parent, err := Verify(in.ParentToken, func(kid, _ string) (crypto.PublicKey, error) {
		if kid != keys.KID {
			return nil, ErrInvalid
		}
		return keys.PublicKey, nil
	}, issuer, service)
	if err != nil || parent.Depth >= MaxDepth || parent.Resource != in.Resource {
		return nil, ErrInvalid
	}
	c := clone(parent)
	c.Sender, c.Receiver, c.RequestHash = service, in.Receiver, in.RequestHash
	c.ParentOperationID, c.OperationID, c.ID = parent.OperationID, uuid.NewString(), uuid.NewString()
	c.Depth++
	c.Audience = jwt.ClaimStrings{AudiencePrefix + in.Receiver}
	c.IssuedAt = jwt.NewNumericDate(time.Now().UTC().Truncate(time.Second))
	c.NotBefore = jwt.NewNumericDate(c.IssuedAt.Time)
	return sign(keys, c)
}

func Verify(token string, keyFunc jwtx.KeyFunc, issuer, receiver string) (*Claims, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes || keyFunc == nil || issuer == "" || receiver == "" {
		return nil, ErrInvalid
	}
	verified, err := jwtx.Verify(token, keyFunc, &jwtx.VerifyConfig{RequiredIssuer: issuer, RequiredAudience: AudiencePrefix + receiver, AllowedAlgorithms: []string{"EdDSA", "RS256"}, ClockSkew: 5 * time.Second})
	if err != nil {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(verified.Claims)
	if err != nil {
		return nil, ErrInvalid
	}
	var c Claims
	if json.Unmarshal(body, &c) != nil || c.Receiver != receiver || validate(&c) != nil {
		return nil, ErrInvalid
	}
	return &c, nil
}

func (c *Claims) CheckHop(service, resource, requestHash string) error {
	if c == nil || c.Depth < 1 || c.Sender != service || c.Resource != resource || c.RequestHash != requestHash {
		return ErrInvalid
	}
	return nil
}

func validate(c *Claims) error {
	if c.Version != 1 || c.TokenUse != TokenUse || c.Subject != "" || c.Origin.Validate() != nil || c.Issuer == "" || len(c.Issuer) > 512 || c.Receiver == "" ||
		!caller.ValidReference(c.Receiver) || !caller.ValidReference(c.Sender) || c.Resource == "" || !caller.ValidReference(c.Resource) ||
		len(c.Audience) != 1 || c.Audience[0] != AudiencePrefix+c.Receiver || !validID(c.ID) || !validID(c.OperationID) || !validHash(c.RequestHash) ||
		c.Depth < 0 || c.Depth > MaxDepth || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt == nil {
		return ErrInvalid
	}
	if c.Depth == 0 && (c.Sender != "" || c.ParentOperationID != "") || c.Depth > 0 && (c.Sender == "" || !validID(c.ParentOperationID)) {
		return ErrInvalid
	}
	now := time.Now()
	lifetime := c.ExpiresAt.Sub(c.IssuedAt.Time)
	if lifetime <= 0 || lifetime > MaxLifetime || !c.NotBefore.Equal(c.IssuedAt.Time) || c.IssuedAt.After(now.Add(5*time.Second)) || !now.Before(c.ExpiresAt.Time) {
		return ErrInvalid
	}
	return nil
}

func sign(keys *jwtx.KeyPair, c *Claims) (*Response, error) {
	if keys == nil || keys.PrivateKey == nil || keys.PublicKey == nil || validate(c) != nil {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, ErrInvalid
	}
	var claims jwt.MapClaims
	if json.Unmarshal(body, &claims) != nil {
		return nil, ErrInvalid
	}
	token, err := jwtx.Sign(keys, claims)
	if err != nil || len(token) > MaxTokenBytes {
		return nil, ErrInvalid
	}
	return &Response{Token: token, ExpiresAt: c.ExpiresAt.Time}, nil
}

func validID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}
func validHash(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(b) == 32 && hex.EncodeToString(b) == value
}

func clone(c *Claims) *Claims {
	copyClaims := *c
	if c.Origin != nil {
		id := *c.Origin
		copyClaims.Origin = &id
	}
	copyClaims.Audience = append(jwt.ClaimStrings(nil), c.Audience...)
	copyClaims.IssuedAt = cloneDate(c.IssuedAt)
	copyClaims.NotBefore = cloneDate(c.NotBefore)
	copyClaims.ExpiresAt = cloneDate(c.ExpiresAt)
	return &copyClaims
}

func cloneDate(date *jwt.NumericDate) *jwt.NumericDate {
	if date == nil {
		return nil
	}
	copyDate := *date
	return &copyDate
}

type contextKey struct{}
type verifiedContext struct {
	claims *Claims
	token  string
}

// WithVerified is for the gateway after signature and request-binding checks.
func WithVerified(ctx context.Context, c *Claims) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, verifiedContext{claims: clone(c)})
}
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(verifiedContext)
	if !ok || c.claims == nil {
		return nil, false
	}
	return clone(c.claims), true
}

// WithVerifiedProof keeps the opaque credential paired with its verified claims
// for gateway forwarding. Only an authenticator may establish this context.
func WithVerifiedProof(ctx context.Context, p *Proof) context.Context {
	if p == nil || p.Claims == nil {
		return context.WithValue(ctx, contextKey{}, verifiedContext{})
	}
	return context.WithValue(ctx, contextKey{}, verifiedContext{claims: clone(p.Claims), token: p.Token})
}

func ProofFromContext(ctx context.Context) (*Proof, bool) {
	c, ok := ctx.Value(contextKey{}).(verifiedContext)
	if !ok || c.claims == nil || c.token == "" {
		return nil, false
	}
	return &Proof{Token: c.token, Claims: clone(c.claims)}, true
}
