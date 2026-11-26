package authnconfig

import (
	"fmt"
	"github.com/ledatu/csar-core/authntokens"
)

// CredentialPublicOAuth exposes the existing generic issuer to public clients.
// URLs and profile aliases are deployment data; admission counters are shared
// protected implementation identities and cannot be reset through configuration.
type CredentialPublicOAuth struct {
	Version               int                      `yaml:"version"`
	Enabled               bool                     `yaml:"enabled"`
	DynamicClients        bool                     `yaml:"dynamic_clients"`
	AuthorizationEndpoint string                   `yaml:"authorization_endpoint"`
	TokenEndpoint         string                   `yaml:"token_endpoint"`
	RegistrationEndpoint  string                   `yaml:"registration_endpoint,omitempty"`
	Profiles              []CredentialOAuthProfile `yaml:"profiles"`
}
type CredentialOAuthProfile struct {
	ProfileID       string   `yaml:"profile_id"`
	ResourceAliases []string `yaml:"resource_aliases,omitempty"`
}

func (c *CredentialConfig) validatePublicOAuth(profiles map[string]bool) error {
	p := c.PublicOAuth
	if p == nil {
		return nil
	}
	if p.Version != 1 || p.Enabled && !c.Enabled || !authntokens.ValidAudience(p.AuthorizationEndpoint) || !authntokens.ValidAudience(p.TokenEndpoint) || p.AuthorizationEndpoint == p.TokenEndpoint || p.DynamicClients && (!authntokens.ValidAudience(p.RegistrationEndpoint) || p.RegistrationEndpoint == p.AuthorizationEndpoint || p.RegistrationEndpoint == p.TokenEndpoint) || !p.DynamicClients && p.RegistrationEndpoint != "" || len(p.Profiles) < 1 || len(p.Profiles) > len(profiles) {
		return fmt.Errorf("credentials: invalid public OAuth policy")
	}
	seen := map[string]bool{}
	resources := map[string]bool{}
	for _, binding := range p.Profiles {
		if !profiles[binding.ProfileID] || seen[binding.ProfileID] || len(binding.ResourceAliases) > 8 {
			return fmt.Errorf("credentials: invalid public OAuth profile")
		}
		seen[binding.ProfileID] = true
		var audience string
		for i := range c.Profiles {
			profile := &c.Profiles[i]
			if profile.ID == binding.ProfileID {
				audience = profile.Audience
			}
		}
		for _, value := range append([]string{audience}, binding.ResourceAliases...) {
			if !authntokens.ValidAudience(value) || resources[value] {
				return fmt.Errorf("credentials: ambiguous public OAuth resource")
			}
			resources[value] = true
		}
	}
	return nil
}
