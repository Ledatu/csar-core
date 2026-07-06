// Package authntokens defines the csar router <-> csar-authn contract for
// authn-managed route token issuance.
package authntokens

import "time"

const (
	ReasonMissingClaim   = "missing_claim"
	ReasonUnknownProfile = "unknown_profile"
	ReasonSigningFailed  = "signing_failed"
)

// IssueTokenRequest asks csar-authn to mint a named route token profile for the
// session being validated.
type IssueTokenRequest struct {
	Profile string `json:"profile"`
}

// ValidateRequest is sent by the router to POST /auth/validate.
type ValidateRequest struct {
	IssueTokens []IssueTokenRequest `json:"issue_tokens,omitempty"`
}

// IssuedToken is a successfully minted token.
type IssuedToken struct {
	Profile   string    `json:"profile"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IssueTokenError reports a profile that could not be issued for an otherwise
// valid session.
type IssueTokenError struct {
	Profile string `json:"profile"`
	Reason  string `json:"reason"`
}

// ValidateResponse is returned by POST /auth/validate for valid sessions.
type ValidateResponse struct {
	Headers map[string]string `json:"headers,omitempty"`
	Tokens  []IssuedToken     `json:"tokens,omitempty"`
	Errors  []IssueTokenError `json:"errors,omitempty"`
}
