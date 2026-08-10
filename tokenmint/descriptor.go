// Package tokenmint performs OAuth2 client_credentials grants on behalf of the
// CSAR token plane, so that a stored "token" can be a short-lived bearer minted
// from a long-lived credential pair rather than a static secret.
//
// The package is split deliberately:
//
//   - Descriptor is *data*. It lives in the token store alongside ordinary
//     secrets and names which grant profile to use and where the credential
//     pair lives.
//   - Profile is *operator configuration*. It carries the token endpoint and
//     everything else that determines where a credential is sent.
//
// That split is the security boundary of this package. See profile.go.
package tokenmint

import (
	"errors"
	"fmt"
	"strings"
)

// KindOAuth2ClientCredentials is the only descriptor kind supported today.
const KindOAuth2ClientCredentials = "oauth2_client_credentials"

// ErrUnknownKind is returned for a descriptor naming a kind this build does
// not implement. Callers must treat it as fatal for that ref: serving a
// descriptor we cannot interpret would mean serving a credential we cannot
// reason about.
var ErrUnknownKind = errors.New("tokenmint: unknown descriptor kind")

// Descriptor is the stored form of a minted credential. It contains no secret
// material — only the grant profile name and the refs of the credential pair.
//
// It is written into the token store by a service (e.g. campaigns during
// account onboarding) and resolved by the coordinator on read-through.
type Descriptor struct {
	Kind            string `json:"kind"`
	GrantProfile    string `json:"grant_profile"`
	ClientIDRef     string `json:"client_id_ref"`
	ClientSecretRef string `json:"client_secret_ref"`
}

// Validate checks structural well-formedness. It deliberately does not check
// whether GrantProfile names a configured profile — that is the resolver's job,
// because the set of profiles is not knowable from the descriptor alone.
func (d *Descriptor) Validate() error {
	if d == nil {
		return fmt.Errorf("tokenmint: descriptor is nil")
	}
	if d.Kind != KindOAuth2ClientCredentials {
		return fmt.Errorf("%w: %q (supported: %q)", ErrUnknownKind, d.Kind, KindOAuth2ClientCredentials)
	}
	if strings.TrimSpace(d.GrantProfile) == "" {
		return fmt.Errorf("tokenmint: descriptor requires a non-empty grant_profile")
	}
	if strings.TrimSpace(d.ClientIDRef) == "" {
		return fmt.Errorf("tokenmint: descriptor requires a non-empty client_id_ref")
	}
	if strings.TrimSpace(d.ClientSecretRef) == "" {
		return fmt.Errorf("tokenmint: descriptor requires a non-empty client_secret_ref")
	}
	if d.ClientIDRef == d.ClientSecretRef {
		return fmt.Errorf("tokenmint: client_id_ref and client_secret_ref must differ")
	}
	return nil
}
