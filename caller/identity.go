// Package caller describes issuer-confirmed token principals. Structural
// validation does not authenticate a token or authorize a request.
package caller

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const Version = 1

type Kind string

const (
	Human       Kind = "human"
	Agent       Kind = "agent"
	Application Kind = "application"
	Service     Kind = "service"
	Unknown     Kind = "unknown"
)

type CredentialKind string

const (
	Session         CredentialKind = "session"
	APIKey          CredentialKind = "api_key"
	OAuthAccess     CredentialKind = "oauth_access"
	DelegationProof CredentialKind = "delegation_proof"
	STS             CredentialKind = "sts"
)

type Assurance string

const (
	Verified Assurance = "verified"
	Legacy   Assurance = "legacy"
)

// Identity describes one authenticated hop. The original caller of a delegated
// operation is a separate Identity; it must not replace the service credential.
// IDs are safe references, never raw tokens, token hashes or display labels.
type Identity struct {
	Version          int            `json:"version"`
	CallerKind       Kind           `json:"caller_kind"`
	CallerID         string         `json:"caller_id,omitempty"`
	OwnerSubject     string         `json:"owner_subject,omitempty"`
	EffectiveSubject string         `json:"effective_subject"`
	CredentialKind   CredentialKind `json:"credential_kind"`
	CredentialID     string         `json:"credential_id,omitempty"`
	ClientID         string         `json:"client_id,omitempty"`
	ConnectionID     string         `json:"connection_id,omitempty"`
	Assurance        Assurance      `json:"assurance"`
}

// Validate checks shape and consistency only. The issuer/registry must establish
// the binding; a request body or a transport name cannot establish identity.
func (id *Identity) Validate() error {
	if id == nil || id.Version != Version {
		return fmt.Errorf("caller: unsupported identity version")
	}
	switch id.CallerKind {
	case Human, Agent, Application, Service:
		if id.CallerID == "" || id.Assurance != Verified {
			return fmt.Errorf("caller: classified principal requires a verified caller ID")
		}
	case Unknown:
		if id.CallerID != "" || id.Assurance != Legacy {
			return fmt.Errorf("caller: legacy principal must remain unclassified")
		}
	default:
		return fmt.Errorf("caller: unsupported caller kind")
	}
	switch id.CredentialKind {
	case Session, APIKey, OAuthAccess, DelegationProof, STS:
	default:
		return fmt.Errorf("caller: unsupported credential kind")
	}
	if id.EffectiveSubject == "" {
		return fmt.Errorf("caller: effective subject is required")
	}
	if (id.CallerKind == Human || id.CallerKind == Agent || id.CallerKind == Application) && id.OwnerSubject == "" {
		return fmt.Errorf("caller: owned principal requires an owner subject")
	}
	for _, field := range []struct{ name, value string }{
		{"caller_id", id.CallerID}, {"owner_subject", id.OwnerSubject},
		{"effective_subject", id.EffectiveSubject}, {"credential_id", id.CredentialID},
		{"connection_id", id.ConnectionID},
	} {
		if !ValidReference(field.value) {
			return fmt.Errorf("caller: invalid %s", field.name)
		}
	}
	if !ValidClientID(id.ClientID) {
		return fmt.Errorf("caller: invalid client_id")
	}
	return nil
}

// ValidClientID accepts legacy references and bounded public HTTPS identifiers
// used by OAuth client metadata documents. This is only an attribution shape
// check: issuers separately validate metadata, redirects and client policy.
// Query strings are excluded so credential-like URL parameters are not copied
// into audit. Other identity references keep their original 256-byte contract.
func ValidClientID(value string) bool {
	if !strings.Contains(value, "://") {
		return ValidReference(value)
	}
	if len(value) > 1024 || !strings.HasPrefix(value, "https://") {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	u, err := url.Parse(value)
	// JSON escapes HTML-sensitive characters even inside base64 gateway headers.
	// Bound that representation too, so accepted identifiers fit the envelope.
	encoded, encodeErr := json.Marshal(value)
	return err == nil && encodeErr == nil && len(encoded) <= 1026 && u.Hostname() != "" && u.User == nil && u.Path != "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(value, "#")
}

// ValidateBinding additionally checks the authenticated envelope. The caller
// must already have verified the credential; this method supplies no authority.
func (id *Identity) ValidateBinding(subject, credentialID string) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if id.EffectiveSubject != subject || id.CredentialID != credentialID {
		return fmt.Errorf("caller: identity does not match authenticated envelope")
	}
	return nil
}

// ValidReference checks a bounded safe reference, including an absent optional
// reference. It does not authenticate its owner or accept credential values.
func ValidReference(value string) bool {
	if len(value) > 256 {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case ':', '.', '_', '-', '/', '@':
		default:
			return false
		}
	}
	return true
}
