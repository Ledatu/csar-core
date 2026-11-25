package authntokens

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/ledatu/csar-core/caller"
)

const (
	ConstraintsVersion       = 1
	MaxNamespaceBytes        = 63
	MaxResourceIDBytes       = 192
	MaxProfileIDBytes        = 128
	MaxAudienceBytes         = 512
	MaxScopeBytes            = 128
	MaxNamespaces            = 16
	MaxScopes                = 32
	MaxSelectedResources     = 256
	MaxDecisionResources     = 100
	MaxCandidateRequestBytes = 64 << 10
	MaxConsentResponseBytes  = 128 << 10
)

// ResourceRef identifies an application-owned object without interpreting its ID.
// Validation establishes structure only, never existence, consent or permission.
type ResourceRef struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	ID        string `json:"id" yaml:"id"`
}

func (r ResourceRef) Validate() error {
	if !ValidNamespace(r.Namespace) || !ValidResourceID(r.ID) {
		return fmt.Errorf("authntokens: invalid resource reference")
	}
	return nil
}

// ScopeRef is independent of ResourceRef. Configured policy owns their mapping.
type ScopeRef struct {
	Type string `json:"type" yaml:"type"`
	ID   string `json:"id" yaml:"id"`
}

func (s ScopeRef) Validate() error {
	if s.Type == "platform" && s.ID == "" || s.Type == "tenant" && s.ID != "" && caller.ValidReference(s.ID) {
		return nil
	}
	return fmt.Errorf("authntokens: invalid authorization scope")
}

type SelectionMode string

const (
	Selected         SelectionMode = "selected"
	CurrentAndFuture SelectionMode = "current_and_future"
)

type ResourceSelection struct {
	Mode      SelectionMode `json:"mode" yaml:"mode"`
	Resources []ResourceRef `json:"resources,omitempty" yaml:"resources,omitempty"`
}

// GrantConstraints is a consent snapshot, not a credential or authorization
// result. The issuer separately binds it to owner, caller, family and deadlines.
// Current configuration and permissions must narrow, never expand, this snapshot.
type GrantConstraints struct {
	Version         int               `json:"version" yaml:"version"`
	ProfileID       string            `json:"profile_id" yaml:"profile_id"`
	ProfileRevision uint64            `json:"profile_revision" yaml:"profile_revision"`
	Audience        string            `json:"audience" yaml:"audience"`
	Scopes          []string          `json:"scopes" yaml:"scopes"`
	Namespaces      []string          `json:"namespaces" yaml:"namespaces"`
	Selection       ResourceSelection `json:"selection" yaml:"selection"`
}

func (g *GrantConstraints) Validate() error {
	if g == nil || g.Version != ConstraintsVersion || !ValidProfileID(g.ProfileID) || g.ProfileRevision == 0 || !ValidAudience(g.Audience) {
		return fmt.Errorf("authntokens: invalid consent profile binding")
	}
	if !validSet(g.Scopes, MaxScopes, ValidScope) || !validSet(g.Namespaces, MaxNamespaces, ValidNamespace) {
		return fmt.Errorf("authntokens: invalid consent scopes or namespaces")
	}
	switch g.Selection.Mode {
	case CurrentAndFuture:
		if len(g.Selection.Resources) != 0 {
			return fmt.Errorf("authntokens: unbounded selection cannot contain resources")
		}
	case Selected:
		if err := ValidateResources(g.Selection.Resources, MaxSelectedResources); err != nil {
			return err
		}
		for _, ref := range g.Selection.Resources {
			if !slices.Contains(g.Namespaces, ref.Namespace) {
				return fmt.Errorf("authntokens: selection outside consented namespaces")
			}
		}
	default:
		return fmt.Errorf("authntokens: unsupported selection mode")
	}
	return nil
}

// ValidateResources rejects ambiguous batches rather than silently deduplicating
// them. Namespace is part of identity even when two resource IDs are equal.
func ValidateResources(refs []ResourceRef, limit int) error {
	if limit < 1 || limit > MaxSelectedResources || len(refs) < 1 || len(refs) > limit {
		return fmt.Errorf("authntokens: invalid resource count")
	}
	seen := make(map[ResourceRef]struct{}, len(refs))
	for _, ref := range refs {
		if err := ref.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[ref]; duplicate {
			return fmt.Errorf("authntokens: duplicate resource reference")
		}
		seen[ref] = struct{}{}
	}
	return nil
}

func ValidNamespace(value string) bool {
	if len(value) == 0 || len(value) > MaxNamespaceBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidResourceID(value string) bool { return validLiteral(value, MaxResourceIDBytes) }
func ValidProfileID(value string) bool  { return validLiteral(value, MaxProfileIDBytes) }

func validLiteral(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}

// ValidScope accepts a single bounded header-safe OAuth scope, not a scope list.
func ValidScope(value string) bool {
	if len(value) == 0 || len(value) > MaxScopeBytes {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e || c == ',' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// ValidAudience checks an exact configured HTTPS identifier. It does not fetch
// the URL, normalize aliases or establish trust in its server.
func ValidAudience(value string) bool {
	if len(value) == 0 || len(value) > MaxAudienceBytes || !strings.HasPrefix(value, "https://") || strings.ContainsAny(value, "*#?\\") {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e || c == ',' || c == '"' {
			return false
		}
	}
	u, err := url.Parse(value)
	return err == nil && u.Hostname() != "" && u.User == nil && u.Opaque == "" && !strings.HasSuffix(u.Host, ":")
}

func validSet(values []string, limit int, valid func(string) bool) bool {
	if len(values) == 0 || len(values) > limit {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
