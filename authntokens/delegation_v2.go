package authntokens

import (
	"fmt"
	"strings"
	"time"

	"github.com/ledatu/csar-core/caller"
)

const DelegationVersion2 = 2
const (
	AccessResource   = "access-resource"
	AccessResourceV2 = "access-resource-v2"
	GrantExchangeV2  = "grant-exchange-v2"
	GrantDiscoveryV2 = "grant-discovery-v2"
	GrantResourceV2  = "grant-resource-v2"
)

func IsDelegationV2(mode string) bool {
	return mode == GrantExchangeV2 || mode == GrantDiscoveryV2 || mode == GrantResourceV2 || mode == AccessResourceV2
}

// V2 is separate from v1: namespace/profile authority cannot be silently dropped.
// Purpose retains the three established meanings; route modes explicitly opt in.
type DelegationRequestV2 struct {
	Version   int          `json:"version"`
	Token     string       `json:"token"`
	Purpose   string       `json:"purpose"`
	ProfileID string       `json:"profile_id"`
	Audience  string       `json:"audience"`
	Scope     string       `json:"scope"`
	Namespace string       `json:"namespace"`
	Resource  *ResourceRef `json:"resource,omitempty"`
}
type DelegationResultV2 struct {
	Version         int              `json:"version"`
	Active          bool             `json:"active"`
	Purpose         string           `json:"purpose,omitempty"`
	ProfileID       string           `json:"profile_id,omitempty"`
	ProfileRevision uint64           `json:"profile_revision,omitempty"`
	Audience        string           `json:"audience,omitempty"`
	Scope           string           `json:"scope,omitempty"`
	Namespace       string           `json:"namespace,omitempty"`
	Resource        *ResourceRef     `json:"resource,omitempty"`
	AuthorizedScope *ScopeRef        `json:"authorized_scope,omitempty"`
	Identity        *caller.Identity `json:"identity,omitempty"`
	ExpiresAt       time.Time        `json:"expires_at,omitzero"`
	DelegatedToken  string           `json:"delegated_token,omitempty"`
}

func ValidCredentialBearer(token string) bool {
	if len(token) < 1 || len(token) > 4096 {
		return false
	}
	for _, c := range token {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~+/=", c) {
			continue
		}
		return false
	}
	return true
}
func (r *DelegationRequestV2) Validate() error {
	if r == nil || r.Version != 2 || !ValidCredentialBearer(r.Token) || (!IsDelegation(r.Purpose) && r.Purpose != AccessResource) || !ValidProfileID(r.ProfileID) || !ValidAudience(r.Audience) || !ValidScope(r.Scope) || !ValidNamespace(r.Namespace) {
		return fmt.Errorf("invalid v2 delegation request")
	}
	if (r.Purpose == GrantResource || r.Purpose == AccessResource) != (r.Resource != nil) || r.Resource != nil && (r.Resource.Validate() != nil || r.Resource.Namespace != r.Namespace) {
		return fmt.Errorf("invalid v2 resource binding")
	}
	return nil
}

// ValidateFor verifies the complete echoed operation and classified identity.
// A caller must also enforce trusted issuer transport and freshness per request.
func (out *DelegationResultV2) ValidateFor(in *DelegationRequestV2, now time.Time) error {
	deny := fmt.Errorf("invalid v2 delegation response")
	if in.Validate() != nil || out == nil || out.Version != 2 || !out.Active || out.ProfileRevision == 0 || out.Purpose != in.Purpose || out.ProfileID != in.ProfileID || out.Audience != in.Audience || out.Scope != in.Scope || out.Namespace != in.Namespace || !out.ExpiresAt.After(now) || out.Identity.Validate() != nil {
		return deny
	}
	id := out.Identity
	if (id.CallerKind != caller.Agent && id.CallerKind != caller.Application) || id.OwnerSubject != id.EffectiveSubject || id.CredentialID == "" || id.Assurance != caller.Verified {
		return deny
	}
	if in.Purpose == GrantExchange || in.Purpose == AccessResource {
		if id.CredentialKind != caller.APIKey && id.CredentialKind != caller.OAuthAccess {
			return deny
		}
	} else if id.CredentialKind != caller.DelegationProof {
		return deny
	}
	if (out.Resource == nil) != (in.Resource == nil) || out.Resource != nil && *out.Resource != *in.Resource {
		return deny
	}
	if in.Purpose == GrantResource || in.Purpose == AccessResource {
		if out.AuthorizedScope == nil || out.AuthorizedScope.Validate() != nil || out.DelegatedToken != "" {
			return deny
		}
	} else if out.AuthorizedScope != nil {
		return deny
	}
	if in.Purpose == GrantExchange {
		if !ValidCredentialBearer(out.DelegatedToken) || out.DelegatedToken == in.Token {
			return deny
		}
	} else if out.DelegatedToken != "" {
		return deny
	}
	return nil
}
