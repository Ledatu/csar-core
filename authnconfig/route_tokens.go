package authnconfig

import (
	"fmt"
	"strings"
	"time"

	"github.com/ledatu/csar-core/secret"
	"gopkg.in/yaml.v3"
)

const (
	RouteTokenMissingFailClosed = "fail_closed"
	RouteTokenMissingOmit       = "omit"

	RouteTokenClaimString = "string"
	RouteTokenClaimInt    = "int"
	RouteTokenClaimBool   = "bool"

	defaultRouteTokenTTL    = 5 * time.Minute
	defaultRouteTokenMaxTTL = time.Hour
	defaultRouteTokenLeeway = 30 * time.Second
)

// RouteTokenConfig describes an authn-owned route token profile.
type RouteTokenConfig struct {
	Enabled        bool                   `yaml:"enabled"`
	Algorithm      string                 `yaml:"algorithm,omitempty"`
	Secret         secret.Secret          `yaml:"secret,omitempty"`
	TTL            Duration               `yaml:"ttl,omitempty"`
	MaxTTL         Duration               `yaml:"max_ttl,omitempty"`
	Leeway         Duration               `yaml:"leeway,omitempty"`
	Issuer         string                 `yaml:"issuer,omitempty"`
	Audience       []string               `yaml:"audience,omitempty"`
	OnMissingClaim string                 `yaml:"on_missing_claim,omitempty"`
	StaticClaims   map[string]interface{} `yaml:"static_claims,omitempty"`
	Claims         map[string]ClaimSource `yaml:"claims,omitempty"`
}

// ClaimSource maps a JWT claim to a value resolved from the authenticated user,
// session, or linked OAuth account.
type ClaimSource struct {
	Source   string `yaml:"source"`
	As       string `yaml:"as,omitempty"`
	Required *bool  `yaml:"required,omitempty"`
}

// UnmarshalYAML accepts either "user.email" or {source: user.email, as: string}.
func (c *ClaimSource) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		c.Source = value.Value
		return nil
	}
	type claimSourceAlias ClaimSource
	var alias claimSourceAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*c = ClaimSource(alias)
	return nil
}

// UnmarshalYAML accepts audience as either a string or a string list.
func (r *RouteTokenConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Enabled        bool                   `yaml:"enabled"`
		Algorithm      string                 `yaml:"algorithm,omitempty"`
		Secret         secret.Secret          `yaml:"secret,omitempty"`
		TTL            Duration               `yaml:"ttl,omitempty"`
		MaxTTL         Duration               `yaml:"max_ttl,omitempty"`
		Leeway         Duration               `yaml:"leeway,omitempty"`
		Issuer         string                 `yaml:"issuer,omitempty"`
		Audience       yaml.Node              `yaml:"audience"`
		OnMissingClaim string                 `yaml:"on_missing_claim,omitempty"`
		StaticClaims   map[string]interface{} `yaml:"static_claims,omitempty"`
		Claims         map[string]ClaimSource `yaml:"claims,omitempty"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*r = RouteTokenConfig{
		Enabled:        raw.Enabled,
		Algorithm:      raw.Algorithm,
		Secret:         raw.Secret,
		TTL:            raw.TTL,
		MaxTTL:         raw.MaxTTL,
		Leeway:         raw.Leeway,
		Issuer:         raw.Issuer,
		OnMissingClaim: raw.OnMissingClaim,
		StaticClaims:   raw.StaticClaims,
		Claims:         raw.Claims,
	}
	if raw.Audience.Kind == 0 {
		return nil
	}
	switch raw.Audience.Kind {
	case yaml.ScalarNode:
		if raw.Audience.Value != "" {
			r.Audience = []string{raw.Audience.Value}
		}
	case yaml.SequenceNode:
		var aud []string
		if err := raw.Audience.Decode(&aud); err != nil {
			return err
		}
		r.Audience = aud
	default:
		return fmt.Errorf("audience must be a string or string list")
	}
	return nil
}

func (c *Config) applyRouteTokenDefaults() {
	for name := range c.RouteTokens {
		profile := c.RouteTokens[name]
		if profile.Algorithm == "" {
			profile.Algorithm = "HS256"
		}
		if profile.TTL.Duration == 0 {
			profile.TTL = NewDuration(defaultRouteTokenTTL)
		}
		if profile.MaxTTL.Duration == 0 {
			profile.MaxTTL = NewDuration(defaultRouteTokenMaxTTL)
		}
		if profile.Leeway.Duration == 0 {
			profile.Leeway = NewDuration(defaultRouteTokenLeeway)
		}
		if profile.OnMissingClaim == "" {
			profile.OnMissingClaim = RouteTokenMissingFailClosed
		}
		for claim, source := range profile.Claims {
			if source.As == "" {
				source.As = RouteTokenClaimString
			}
			profile.Claims[claim] = source
		}
		c.RouteTokens[name] = profile
	}
}

func (c *Config) validateRouteTokens() error {
	for name := range c.RouteTokens {
		profile := c.RouteTokens[name]
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("route_tokens contains an empty profile name")
		}
		if !profile.Enabled {
			continue
		}
		if profile.Algorithm != "HS256" {
			return fmt.Errorf("route_tokens.%s.algorithm must be HS256, got %q", name, profile.Algorithm)
		}
		if profile.Secret.IsEmpty() {
			return fmt.Errorf("route_tokens.%s.secret is required when enabled", name)
		}
		if profile.TTL.Duration <= 0 {
			return fmt.Errorf("route_tokens.%s.ttl must be greater than zero", name)
		}
		if profile.MaxTTL.Duration <= 0 {
			return fmt.Errorf("route_tokens.%s.max_ttl must be greater than zero", name)
		}
		if profile.TTL.Duration > profile.MaxTTL.Duration {
			return fmt.Errorf("route_tokens.%s.ttl must not exceed max_ttl", name)
		}
		if profile.Leeway.Duration < 0 {
			return fmt.Errorf("route_tokens.%s.leeway must be greater than or equal to zero", name)
		}
		switch profile.OnMissingClaim {
		case RouteTokenMissingFailClosed, RouteTokenMissingOmit:
		default:
			return fmt.Errorf("route_tokens.%s.on_missing_claim must be %q or %q", name, RouteTokenMissingFailClosed, RouteTokenMissingOmit)
		}
		for claim, source := range profile.Claims {
			if strings.TrimSpace(claim) == "" {
				return fmt.Errorf("route_tokens.%s.claims contains an empty claim name", name)
			}
			if err := validateRouteTokenClaimSource(source); err != nil {
				return fmt.Errorf("route_tokens.%s.claims.%s: %w", name, claim, err)
			}
		}
	}
	return nil
}

func validateRouteTokenClaimSource(source ClaimSource) error {
	if source.Source == "" {
		return fmt.Errorf("source is required")
	}
	switch source.As {
	case RouteTokenClaimString, RouteTokenClaimInt, RouteTokenClaimBool:
	default:
		return fmt.Errorf("as must be %q, %q, or %q", RouteTokenClaimString, RouteTokenClaimInt, RouteTokenClaimBool)
	}

	parts := strings.Split(source.Source, ".")
	switch {
	case len(parts) == 2 && parts[0] == "user":
		switch parts[1] {
		case "id", "email", "phone", "display_name":
			return nil
		}
	case len(parts) == 2 && parts[0] == "session" && parts[1] == "id":
		return nil
	case len(parts) >= 3 && parts[0] == "oauth" && parts[1] != "":
		switch parts[2] {
		case "provider_user_id", "email":
			if len(parts) == 3 {
				return nil
			}
		case "metadata":
			if len(parts) == 4 && parts[3] != "" {
				return nil
			}
		}
	}
	return fmt.Errorf("unknown source %q", source.Source)
}
