package authnconfig

import (
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar-core/stsclient"
	"gopkg.in/yaml.v3"
)

// CredentialConfigVersion evolves independently of stored consent formats.
const CredentialConfigVersion = 1

// CredentialConfig declares future generic issuer policy. Current loaders reject
// activation until runtime receivers implement these semantics explicitly.
type CredentialConfig struct {
	PublicOAuth       *CredentialPublicOAuth      `yaml:"public_oauth,omitempty"`
	Decisions         stsclient.ServiceAuthConfig `yaml:"decisions,omitempty"`
	Version           int                         `yaml:"version"`
	Enabled           bool                        `yaml:"enabled"`
	IssuerURL         string                      `yaml:"issuer_url"`
	ConsentURL        string                      `yaml:"consent_url"`
	MutationOrigins   []string                    `yaml:"mutation_origins"`
	ConsentCookieName string                      `yaml:"consent_cookie_name"`
	TrustPolicies     []CredentialTrustPolicy     `yaml:"trust_policies"`
	Profiles          []CredentialProfile         `yaml:"profiles"`
	Receivers         []CredentialReceiver        `yaml:"receivers"`
}

// Each feature selects one dedicated root and exact verified leaf identity.
// Runtime must verify certificate contents/chain isolation; filenames grant no trust.
type CredentialTrustPolicy struct {
	ID     string `yaml:"id"`
	CAFile string `yaml:"ca_file"`
	PeerCN string `yaml:"peer_cn"`
}

// CredentialManualIssuance fixes the accounting family and maximum fixed lifetime.
// Connection is the existing shared connection family; it confers no OAuth client
// or refresh authority. Request bodies cannot select a different family.
type CredentialManualIssuance struct {
	Family string   `yaml:"family"`
	MaxTTL Duration `yaml:"max_ttl"`
}

type CredentialProfile struct {
	ManualIssuance         *CredentialManualIssuance   `yaml:"manual_issuance,omitempty"`
	ID                     string                      `yaml:"id"`
	AcceptedGrantRevisions []uint64                    `yaml:"accepted_grant_revisions,omitempty"`
	Revision               uint64                      `yaml:"revision"`
	Audience               string                      `yaml:"audience"`
	Scopes                 []CredentialScope           `yaml:"scopes"`
	Namespaces             []string                    `yaml:"namespaces"`
	SelectionModes         []authntokens.SelectionMode `yaml:"selection_modes"`
	AccessTTL              Duration                    `yaml:"access_ttl"`
	GrantTTL               Duration                    `yaml:"grant_ttl"`
	ProofTTL               Duration                    `yaml:"proof_ttl"`
	TrustPolicy            string                      `yaml:"trust_policy"`
}

// Authz owns the referenced permission policy, not this issuer declaration.
type CredentialScope struct {
	Scope           string `yaml:"scope"`
	DecisionProfile string `yaml:"decision_profile"`
}

type CredentialReceiver struct {
	Subject     string   `yaml:"subject"`
	Profiles    []string `yaml:"profiles"`
	Operations  []string `yaml:"operations"`
	TrustPolicy string   `yaml:"trust_policy"`
}

func (c *CredentialConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain CredentialConfig
	var decoded plain
	if err := configutil.DecodeStrictYAML(node, &decoded); err != nil {
		return err
	}
	*c = CredentialConfig(decoded)
	return nil
}

func (c *CredentialConfig) validate(generalCAFile string) error {
	return c.validateRuntime(generalCAFile, false)
}
func (c *CredentialConfig) validateRuntime(generalCAFile string, receiver bool) error {
	if c == nil {
		return nil
	}
	if c.Version != CredentialConfigVersion {
		return fmt.Errorf("credentials: unsupported version")
	}
	if c.Enabled && !receiver {
		return fmt.Errorf("credentials: runtime activation is not supported")
	}
	if err := c.Decisions.Validate(); err != nil {
		return fmt.Errorf("credentials: invalid decision transport")
	}
	if c.Enabled && (!c.Decisions.IsConfigured() || !authntokens.ValidAudience(c.Decisions.RouterBaseURL) || !authntokens.ValidAudience(c.Decisions.STSEndpoint) || c.Decisions.RouterTimeout <= 0 || c.Decisions.RouterTimeout > 30*time.Second) {
		return fmt.Errorf("credentials: bounded routed decisions required")
	}
	if !authntokens.ValidAudience(c.IssuerURL) || !authntokens.ValidAudience(c.ConsentURL) ||
		!strings.HasPrefix(c.ConsentCookieName, "__Host-") || len(c.ConsentCookieName) > 128 || !authntokens.ValidProfileID(strings.TrimPrefix(c.ConsentCookieName, "__Host-")) {
		return fmt.Errorf("credentials: invalid public URLs or secure consent cookie")
	}
	if len(c.MutationOrigins) < 1 || len(c.MutationOrigins) > 32 {
		return fmt.Errorf("credentials: invalid mutation origin count")
	}
	origins := make(map[string]bool, len(c.MutationOrigins))
	for _, origin := range c.MutationOrigins {
		if !authntokens.ValidAudience(origin) || origins[origin] {
			return fmt.Errorf("credentials: invalid or duplicate mutation origin")
		}
		u, err := url.Parse(origin)
		if err != nil || origin != u.Scheme+"://"+u.Host {
			return fmt.Errorf("credentials: mutation origin must be exact HTTPS origin")
		}
		origins[origin] = true
	}
	if len(c.TrustPolicies) < 1 || len(c.TrustPolicies) > 32 || len(c.Profiles) < 1 || len(c.Profiles) > 32 || len(c.Receivers) > 64 {
		return fmt.Errorf("credentials: invalid policy collection size")
	}
	trust := make(map[string]bool, len(c.TrustPolicies))
	for _, policy := range c.TrustPolicies {
		if !authntokens.ValidProfileID(policy.ID) || trust[policy.ID] || !authntokens.ValidProfileID(policy.PeerCN) ||
			!filepath.IsAbs(policy.CAFile) || policy.CAFile == "/" || strings.ContainsAny(policy.CAFile, "\x00\r\n") || filepath.Clean(policy.CAFile) != policy.CAFile || strings.TrimSpace(policy.CAFile) != policy.CAFile ||
			(generalCAFile != "" && filepath.Clean(generalCAFile) == policy.CAFile) {
			return fmt.Errorf("credentials: invalid or non-dedicated trust policy")
		}
		trust[policy.ID] = true
	}
	profiles := make(map[string]bool, len(c.Profiles))
	for i := range c.Profiles {
		profile := &c.Profiles[i]
		if profiles[profile.ID] || !trust[profile.TrustPolicy] {
			return fmt.Errorf("credentials: duplicate profile or unknown trust policy")
		}
		if err := profile.validate(); err != nil {
			return err
		}
		profiles[profile.ID] = true
	}
	if err := c.validatePublicOAuth(profiles); err != nil {
		return err
	}
	subjects := make(map[string]bool, len(c.Receivers))
	for _, receiver := range c.Receivers {
		if !strings.HasPrefix(receiver.Subject, "svc:") || receiver.Subject == "svc:" || !caller.ValidReference(receiver.Subject) || subjects[receiver.Subject] || !trust[receiver.TrustPolicy] ||
			len(receiver.Profiles) < 1 || len(receiver.Profiles) > len(profiles) || len(receiver.Operations) < 1 || len(receiver.Operations) > 2 {
			return fmt.Errorf("credentials: invalid receiver capability")
		}
		seen := make(map[string]bool, len(receiver.Profiles))
		for _, id := range receiver.Profiles {
			if !profiles[id] || seen[id] {
				return fmt.Errorf("credentials: unknown or duplicate receiver profile")
			}
			seen[id] = true
		}
		for i, operation := range receiver.Operations {
			if operation != "inspect" && operation != "evaluate" || slices.Contains(receiver.Operations[:i], operation) {
				return fmt.Errorf("credentials: invalid receiver operation")
			}
		}
		subjects[receiver.Subject] = true
	}
	return nil
}

func (p *CredentialProfile) validate() error {
	if m := p.ManualIssuance; m != nil {
		if (m.Family != "api_key" && m.Family != "connection") || m.MaxTTL.Duration < time.Second || m.MaxTTL.Duration%time.Second != 0 || m.MaxTTL.Duration > p.GrantTTL.Duration {
			return fmt.Errorf("credentials: invalid manual issuance policy")
		}
		if m.Family == "connection" && (m.MaxTTL.Duration < time.Hour || m.MaxTTL.Duration > 168*time.Hour) {
			return fmt.Errorf("credentials: manual connection lifetime must be within 1–168 hours")
		}
	}

	if p.AcceptedGrantRevisions != nil {
		if len(p.AcceptedGrantRevisions) < 1 || len(p.AcceptedGrantRevisions) > 32 || !slices.Contains(p.AcceptedGrantRevisions, p.Revision) {
			return fmt.Errorf("credentials: invalid accepted revisions")
		}
		for i, r := range p.AcceptedGrantRevisions {
			if r == 0 || r > p.Revision || slices.Contains(p.AcceptedGrantRevisions[:i], r) {
				return fmt.Errorf("credentials: invalid accepted revisions")
			}
		}
	}

	if !authntokens.ValidProfileID(p.ID) || p.Revision == 0 || !authntokens.ValidAudience(p.Audience) || !authntokens.ValidNamespaces(p.Namespaces) ||
		p.AccessTTL.Duration <= 0 || p.GrantTTL.Duration <= 0 || p.ProofTTL.Duration <= 0 || p.AccessTTL.Duration > p.GrantTTL.Duration || p.ProofTTL.Duration > p.AccessTTL.Duration {
		return fmt.Errorf("credentials: invalid profile binding or lifetimes")
	}
	scopes := make([]string, 0, len(p.Scopes))
	for _, scope := range p.Scopes {
		if !authntokens.ValidProfileID(scope.DecisionProfile) {
			return fmt.Errorf("credentials: invalid decision profile reference")
		}
		scopes = append(scopes, scope.Scope)
	}
	if !authntokens.ValidScopes(scopes) || len(p.SelectionModes) < 1 || len(p.SelectionModes) > 2 {
		return fmt.Errorf("credentials: invalid scopes or selection modes")
	}
	for i, mode := range p.SelectionModes {
		if mode != authntokens.Selected && mode != authntokens.CurrentAndFuture || slices.Contains(p.SelectionModes[:i], mode) {
			return fmt.Errorf("credentials: invalid selection mode")
		}
	}
	return nil
}

// Narrow returns derived effective consent, preserving the immutable original
// revision. It establishes no current permission or resource existence.
func (p *CredentialProfile) Narrow(g *authntokens.GrantConstraints) (*authntokens.GrantConstraints, error) {
	deny := fmt.Errorf("credentials: consent is incompatible with current policy")
	if p == nil || p.validate() != nil || g.Validate() != nil || g.ProfileID != p.ID || g.Audience != p.Audience || !p.AcceptsGrantRevision(g.ProfileRevision) || !slices.Contains(p.SelectionModes, g.Selection.Mode) {
		return nil, deny
	}
	out := *g
	out.Scopes = nil
	out.Namespaces = nil
	out.Selection.Resources = nil
	for _, scope := range g.Scopes {
		if slices.ContainsFunc(p.Scopes, func(s CredentialScope) bool { return s.Scope == scope }) {
			out.Scopes = append(out.Scopes, scope)
		}
	}
	for _, ns := range g.Namespaces {
		if slices.Contains(p.Namespaces, ns) {
			out.Namespaces = append(out.Namespaces, ns)
		}
	}
	for _, ref := range g.Selection.Resources {
		if slices.Contains(out.Namespaces, ref.Namespace) {
			out.Selection.Resources = append(out.Selection.Resources, ref)
		}
	}
	if out.Validate() != nil {
		return nil, deny
	}
	return &out, nil
}
func (p *CredentialProfile) AcceptsGrantRevision(r uint64) bool {
	if p == nil || r == 0 {
		return false
	}
	if p.AcceptedGrantRevisions == nil {
		return r == p.Revision
	}
	return slices.Contains(p.AcceptedGrantRevisions, r)
}
