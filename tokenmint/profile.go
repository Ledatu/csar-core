package tokenmint

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
)

// Body styles for the token request.
const (
	BodyStyleJSON = "json"
	BodyStyleForm = "form"
)

// Profile describes how to execute a client_credentials grant against one
// upstream token endpoint.
//
// SECURITY: profiles are operator configuration and MUST NOT become
// data-driven. TokenURL is the destination a long-lived client_secret is sent
// to; if a Descriptor (which any service holding write access to the token
// store can author) could supply or override it, an attacker could redirect
// every credential in the store to an endpoint they control. The descriptor
// names a profile; only the operator defines what that profile is. Every other
// control in this package assumes that invariant holds.
type Profile struct {
	// TokenURL is the token endpoint. Must be https:// and its host must
	// appear in Config.AllowedHosts.
	TokenURL string `yaml:"token_url"`

	// BodyStyle selects how credentials are encoded: "json" or "form".
	BodyStyle string `yaml:"body_style"`

	// StaticParams are sent verbatim with every request, e.g.
	// {grant_type: client_credentials}.
	StaticParams map[string]string `yaml:"static_params"`

	// Request field names for the credential pair.
	ClientIDParam     string `yaml:"client_id_param"`
	ClientSecretParam string `yaml:"client_secret_param"`

	// Response field names. Dots select nested objects, e.g. "data.token".
	AccessTokenPath string `yaml:"access_token_path"`
	ExpiresInPath   string `yaml:"expires_in_path"`
	TokenTypePath   string `yaml:"token_type_path"`

	// ExpectedTokenType, when non-empty, is compared case-insensitively
	// against the response token type. A mismatch fails the mint rather than
	// injecting a credential the upstream did not agree to issue.
	ExpectedTokenType string `yaml:"expected_token_type"`

	// DefaultExpiresIn applies when the response omits an expiry.
	DefaultExpiresIn time.Duration `yaml:"default_expires_in"`

	// ExpiresInHaircut scales the advertised lifetime before it is trusted,
	// absorbing clock skew and upstream rounding. 0.9 means "treat a 30m token
	// as 27m". Must be in (0, 1].
	ExpiresInHaircut float64 `yaml:"expires_in_haircut"`

	// RefreshMargin is how far ahead of hard expiry a token becomes eligible
	// for background refresh. Between the refresh point and hard expiry the
	// existing token keeps being served, so an upstream outage of up to
	// (lifetime - RefreshMargin) is invisible to traffic.
	RefreshMargin time.Duration `yaml:"refresh_margin"`

	// MinRefreshInterval is the hard floor between two mints for the same
	// credential pair, regardless of demand.
	MinRefreshInterval time.Duration `yaml:"min_refresh_interval"`

	// Backoff after a failed mint. AuthErrorBackoff applies to responses that
	// indicate bad or revoked credentials, where fast retries are pure waste
	// and risk upstream account lockout.
	ErrorBackoffBase time.Duration `yaml:"error_backoff_base"`
	ErrorBackoffMax  time.Duration `yaml:"error_backoff_max"`
	AuthErrorBackoff time.Duration `yaml:"auth_error_backoff"`

	// IdleTTL is how long a minted entry survives without being served before
	// it is evicted. This is what stops accounts that receive no traffic from
	// consuming upstream mint quota indefinitely.
	IdleTTL time.Duration `yaml:"idle_ttl"`

	// Timeout bounds a single token request.
	Timeout time.Duration `yaml:"timeout"`

	// MaxResponseBytes caps the token response body.
	MaxResponseBytes int64 `yaml:"max_response_bytes"`

	// MaxMintsPerMinute bounds outbound mints across all accounts using this
	// profile. It is the backstop against a cold-start stampede.
	MaxMintsPerMinute float64 `yaml:"max_mints_per_minute"`

	// SecretRefScopeSegments is how many leading path segments of the
	// descriptor's own ref the credential refs must share.
	//
	// This is the control that stops a descriptor from being an arbitrary read
	// primitive over the token store. With a ref layout of
	// accounts/{marketplace}/{external_id}/..., a value of 3 confines a
	// descriptor to its own account namespace.
	SecretRefScopeSegments int `yaml:"secret_ref_scope_segments"`
}

// Config is the full mint configuration: the profile set plus the closed list
// of hosts any profile is permitted to contact.
type Config struct {
	// AllowedHosts is the closed set of token-endpoint hosts. Checked at load
	// time and again at request time.
	AllowedHosts []string `yaml:"allowed_hosts"`

	// AllowPrivate permits http:// and internal addresses. Development only;
	// callers must refuse to enable it in production.
	AllowPrivate bool `yaml:"allow_private"`

	Profiles map[string]Profile `yaml:"profiles"`

	allowedHosts map[string]bool
}

// LoadConfigFile reads and validates a mint configuration file.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tokenmint: read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("tokenmint: parse config %q: %w", path, err)
	}

	configutil.ExpandEnvInStruct(reflect.ValueOf(&cfg).Elem())

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("tokenmint: config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	for name := range c.Profiles {
		p := c.Profiles[name]
		if p.BodyStyle == "" {
			p.BodyStyle = BodyStyleJSON
		}
		if p.ClientIDParam == "" {
			p.ClientIDParam = "client_id"
		}
		if p.ClientSecretParam == "" {
			p.ClientSecretParam = "client_secret"
		}
		if p.AccessTokenPath == "" {
			p.AccessTokenPath = "access_token"
		}
		if p.ExpiresInPath == "" {
			p.ExpiresInPath = "expires_in"
		}
		if p.TokenTypePath == "" {
			p.TokenTypePath = "token_type"
		}
		if p.DefaultExpiresIn <= 0 {
			p.DefaultExpiresIn = 15 * time.Minute
		}
		if p.ExpiresInHaircut <= 0 {
			p.ExpiresInHaircut = 0.9
		}
		if p.RefreshMargin <= 0 {
			p.RefreshMargin = 5 * time.Minute
		}
		if p.MinRefreshInterval <= 0 {
			p.MinRefreshInterval = time.Minute
		}
		if p.ErrorBackoffBase <= 0 {
			p.ErrorBackoffBase = 30 * time.Second
		}
		if p.ErrorBackoffMax <= 0 {
			p.ErrorBackoffMax = 5 * time.Minute
		}
		if p.AuthErrorBackoff <= 0 {
			p.AuthErrorBackoff = 15 * time.Minute
		}
		if p.IdleTTL <= 0 {
			p.IdleTTL = 90 * time.Minute
		}
		if p.Timeout <= 0 {
			p.Timeout = 8 * time.Second
		}
		if p.MaxResponseBytes <= 0 {
			p.MaxResponseBytes = 64 << 10
		}
		if p.MaxMintsPerMinute <= 0 {
			p.MaxMintsPerMinute = 30
		}
		if p.SecretRefScopeSegments <= 0 {
			p.SecretRefScopeSegments = 3
		}
		c.Profiles[name] = p
	}
}

// Validate applies defaults and then fails closed on anything ambiguous. A
// coordinator that starts with a broken mint config and then 502s every
// affected route is worse than one that refuses to start.
//
// Defaults are applied here rather than only on the file path so that a Config
// built in Go behaves identically to one loaded from YAML.
func (c *Config) Validate() error {
	if len(c.Profiles) == 0 {
		return fmt.Errorf("at least one profile is required")
	}

	c.applyDefaults()

	c.allowedHosts = make(map[string]bool, len(c.AllowedHosts))
	for _, h := range c.AllowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			c.allowedHosts[h] = true
		}
	}

	for name := range c.Profiles {
		p := c.Profiles[name]
		if err := c.validateProfile(name, &p); err != nil {
			return fmt.Errorf("profile %q: %w", name, err)
		}
	}
	return nil
}

func (c *Config) validateProfile(name string, p *Profile) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("profile name must not be empty")
	}

	u, err := url.Parse(p.TokenURL)
	if err != nil {
		return fmt.Errorf("token_url %q is not a valid URL: %w", p.TokenURL, err)
	}
	if u.Host == "" {
		return fmt.Errorf("token_url %q has no host", p.TokenURL)
	}
	if u.Scheme != "https" && !c.AllowPrivate {
		return fmt.Errorf("token_url %q must use https (allow_private is off)", p.TokenURL)
	}
	if !c.HostAllowed(u.Hostname()) {
		return fmt.Errorf("token_url host %q is not in allowed_hosts", u.Hostname())
	}

	switch p.BodyStyle {
	case BodyStyleJSON, BodyStyleForm:
	default:
		return fmt.Errorf("body_style %q must be %q or %q", p.BodyStyle, BodyStyleJSON, BodyStyleForm)
	}

	if p.ExpiresInHaircut <= 0 || p.ExpiresInHaircut > 1 {
		return fmt.Errorf("expires_in_haircut %v must be in (0, 1]", p.ExpiresInHaircut)
	}
	if p.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if p.MaxResponseBytes <= 0 {
		return fmt.Errorf("max_response_bytes must be positive")
	}
	if p.SecretRefScopeSegments < 1 {
		return fmt.Errorf("secret_ref_scope_segments must be at least 1")
	}
	if p.RefreshMargin >= p.DefaultExpiresIn {
		return fmt.Errorf("refresh_margin %v must be shorter than default_expires_in %v", p.RefreshMargin, p.DefaultExpiresIn)
	}
	return nil
}

// HostAllowed reports whether host is in the closed allowlist. It is called
// both at config load and again immediately before each request, so that a
// profile can never reach an endpoint the operator did not name.
func (c *Config) HostAllowed(host string) bool {
	return c.allowedHosts[strings.ToLower(strings.TrimSpace(host))]
}

// Profile looks up a profile by name, returning a copy so callers cannot
// mutate shared configuration. The boolean is false for unknown names;
// callers must never fall back to a default profile.
func (c *Config) Profile(name string) (Profile, bool) {
	p, ok := c.Profiles[name]
	return p, ok
}

// ProfileRef is Profile without the copy, for hot paths that only read.
func (c *Config) ProfileRef(name string) (*Profile, bool) {
	p, ok := c.Profiles[name]
	if !ok {
		return nil, false
	}
	return &p, true
}

// MaxTimeout returns the longest per-request timeout across all profiles.
// Callers use it to check that their own enclosing deadlines are wide enough
// to let a mint finish.
func (c *Config) MaxTimeout() time.Duration {
	var max time.Duration
	for name := range c.Profiles {
		if t := c.Profiles[name].Timeout; t > max {
			max = t
		}
	}
	return max
}
