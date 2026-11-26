package authntokens

import (
	"fmt"
	"github.com/ledatu/csar-core/caller"
)

// AccountBinding describes verified attribution, never a tenant or permission.
// Identity supplies immutable owner/effective/caller/grant references; credential
// bindings also retain the original profile revision and exact audience.
type AccountBinding struct {
	Kind            string `json:"kind"`
	ProfileID       string `json:"profile_id,omitempty"`
	ProfileRevision uint64 `json:"profile_revision,omitempty"`
	Audience        string `json:"audience,omitempty"`
}

func (b *AccountBinding) Validate(id *caller.Identity) error {
	deny := fmt.Errorf("invalid account binding")
	if b == nil || id.Validate() != nil || id.OwnerSubject != id.EffectiveSubject {
		return deny
	}
	switch b.Kind {
	case "subject":
		if id.CallerKind != caller.Human || id.CredentialKind != caller.Session || id.CallerID != id.OwnerSubject || b.ProfileID != "" || b.ProfileRevision != 0 || b.Audience != "" {
			return deny
		}
	case "credential":
		if (id.CallerKind != caller.Agent && id.CallerKind != caller.Application) || id.CredentialID == "" || (id.CredentialKind != caller.APIKey && id.CredentialKind != caller.OAuthAccess && id.CredentialKind != caller.DelegationProof) || !ValidProfileID(b.ProfileID) || b.ProfileRevision == 0 || !ValidAudience(b.Audience) {
			return deny
		}
	default:
		return deny
	}
	return nil
}
func (b *AccountBinding) Clone() *AccountBinding {
	if b == nil {
		return nil
	}
	copyBinding := *b
	return &copyBinding
}
