package authntokens

import "time"

// The purpose determines which credential the issuer may consume and which
// authority a successful response conveys. Each audience has its own issuer policy.
const (
	GrantExchange  = "grant-exchange"
	GrantDiscovery = "grant-discovery"
	GrantResource  = "grant-resource"
)

func IsDelegation(mode string) bool {
	return mode == GrantExchange || mode == GrantDiscovery || mode == GrantResource
}

// DelegationRequest is sent by a mutually authenticated router. ResourceID
// comes from the matched route. Only resource consumption accepts this field.
type DelegationRequest struct {
	Token      string `json:"token"`
	Purpose    string `json:"purpose"`
	Audience   string `json:"audience"`
	Scope      string `json:"scope"`
	ResourceID string `json:"resource_id,omitempty"`
}

// DelegationResult binds the verified identity to the requested operation.
// Only exchange returns a fresh proof. Only resource consumption returns a
// resource ID. Exchange may supply a default tenant for a single-resource grant.
type DelegationResult struct {
	Active         bool      `json:"active"`
	Purpose        string    `json:"purpose,omitempty"`
	Audience       string    `json:"audience,omitempty"`
	Scope          string    `json:"scope,omitempty"`
	Subject        string    `json:"subject,omitempty"`
	CredentialID   string    `json:"credential_id,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitzero"`
	ResourceID     string    `json:"resource_id,omitempty"`
	Tenant         string    `json:"tenant,omitempty"`
	DelegatedToken string    `json:"delegated_token,omitempty"`
}
