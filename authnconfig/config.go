// Package authnconfig defines the csar-authn configuration schema and
// provides loading + validation. It is intentionally free of runtime
// dependencies (no DB, no gRPC, no HTTP) so that csar-helper can
// validate authn configs without pulling in the full service.
package authnconfig

import (
	"fmt"
	"reflect"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
)

// Config is the top-level csar-authn configuration.
type Config struct {
	ListenAddr             string                   `yaml:"listen_addr"`
	BaseURL                string                   `yaml:"base_url"`
	FrontendURL            string                   `yaml:"frontend_url"`
	AllowedRedirectOrigins []string                 `yaml:"allowed_redirect_origins"`
	TLS                    configutil.TLSSection    `yaml:"tls"`
	Health                 configutil.HealthSection `yaml:"health"`
	Log                    configutil.LogSection    `yaml:"log"`
	MetricsAddr            string                   `yaml:"metrics_addr"`
	Database               DatabaseConfig           `yaml:"database"`
	JWT                    JWTConfig                `yaml:"jwt"`
	OAuth                  OAuthConfig              `yaml:"oauth"`
	Cookie                 CookieConfig             `yaml:"cookie"`
	Session                SessionConfig            `yaml:"session"`
	Redis                  *RedisConfig             `yaml:"redis,omitempty"`
	STS                    STSConfig                `yaml:"sts,omitempty"`
	Authz                  AuthzConfig              `yaml:"authz,omitempty"`
	BotVerify              *BotVerifyConfig          `yaml:"bot_verify,omitempty"`
}

// AuthzConfig configures the connection to csar-authz for permissions endpoints.
type AuthzConfig struct {
	Enabled  bool           `yaml:"enabled"`
	Endpoint string         `yaml:"endpoint"`
	TLS      AuthzTLSConfig `yaml:"tls"`
}

// AuthzTLSConfig controls TLS for the authn -> authz gRPC connection.
type AuthzTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CAFile   string `yaml:"ca_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

// BotVerifyConfig controls bot-based identity verification (Telegram, VK, etc.)
type BotVerifyConfig struct {
	Enabled          bool              `yaml:"enabled"`
	CodeTTL          Duration          `yaml:"code_ttl"`
	MaxPendingPerIP  int               `yaml:"max_pending_per_ip"`
	AllowedProviders []string          `yaml:"allowed_providers"`
	Bots             []BotProviderInfo `yaml:"bots"`
}

// BotProviderInfo describes a bot that users can send verification codes to.
type BotProviderInfo struct {
	Provider    string `yaml:"provider"`
	BotUsername string `yaml:"bot_username"`
}

// STSConfig controls the Security Token Service for service-to-service auth.
// Service accounts are managed in the database via the admin API.
// Bootstrap accounts defined in config take precedence over DB accounts
// with the same name, ensuring cold-start operability.
type STSConfig struct {
	Enabled         bool               `yaml:"enabled"`
	AssertionMaxAge Duration           `yaml:"assertion_max_age"`
	Accounts        []BootstrapAccount `yaml:"accounts"`
}

// BootstrapAccount defines a service account loaded from configuration
// rather than the database. Config-defined accounts take precedence by name.
type BootstrapAccount struct {
	Name              string   `yaml:"name"`
	PublicKeyPEM      string   `yaml:"public_key_pem"`
	AllowedAudiences  []string `yaml:"allowed_audiences"`
	AllowAllAudiences bool     `yaml:"allow_all_audiences"`
	TokenTTL          Duration `yaml:"token_ttl"`
}

// DatabaseConfig selects the storage backend.
type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// JWTConfig controls token signing and key management.
type JWTConfig struct {
	PrivateKeyFile string   `yaml:"private_key_file"`
	PublicKeyFile  string   `yaml:"public_key_file"`
	Algorithm      string   `yaml:"algorithm"`
	Issuer         string   `yaml:"issuer"`
	Audience       string   `yaml:"audience"`
	TTL            Duration `yaml:"ttl"`
	AutoGenerate   bool     `yaml:"auto_generate"`
	KeyDir         string   `yaml:"key_dir"`
}

// OAuthConfig configures Goth providers and the state cookie secret.
type OAuthConfig struct {
	SessionSecret string           `yaml:"session_secret"`
	Providers     []ProviderConfig `yaml:"providers"`
}

// ProviderConfig defines a single OAuth provider.
type ProviderConfig struct {
	Name         string   `yaml:"name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	CallbackURL  string   `yaml:"callback_url"`
	Scopes       []string `yaml:"scopes"`
	Trusted      bool     `yaml:"trusted"`
}

// CookieConfig controls the session cookie parameters.
type CookieConfig struct {
	Name     string `yaml:"name"`
	Domain   string `yaml:"domain"`
	Secure   bool   `yaml:"secure"`
	SameSite string `yaml:"same_site"`
}

// SessionConfig controls server-side session behaviour.
type SessionConfig struct {
	MaxAge          Duration `yaml:"max_age"`          // absolute session lifetime from creation
	IdleTimeout     Duration `yaml:"idle_timeout"`     // resets on activity (sliding window)
	TouchThreshold  Duration `yaml:"touch_threshold"`  // only write last_seen_at if older than this
	CleanupInterval Duration `yaml:"cleanup_interval"` // how often to purge expired rows
}

// RedisConfig configures an optional Redis connection.
type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// Duration is a type alias for the shared configutil.Duration.
type Duration = configutil.Duration

// NewDuration wraps a time.Duration in a configutil.Duration.
func NewDuration(d time.Duration) Duration {
	return Duration{Duration: d}
}

// LoadFromBytes parses raw YAML bytes into a Config, expanding environment
// variables, applying defaults, and validating.
func LoadFromBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	configutil.ExpandEnvInStruct(reflect.ValueOf(&cfg))

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8081"
	}
	if cfg.JWT.Algorithm == "" {
		cfg.JWT.Algorithm = "RS256"
	}
	if cfg.JWT.TTL.Duration == 0 {
		cfg.JWT.TTL = NewDuration(24 * time.Hour)
	}
	if cfg.JWT.KeyDir == "" {
		cfg.JWT.KeyDir = "./keys"
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "csar_session"
	}
	if cfg.Cookie.SameSite == "" {
		cfg.Cookie.SameSite = "lax"
	}
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "postgres"
	}
	if cfg.Session.MaxAge.Duration == 0 {
		cfg.Session.MaxAge = NewDuration(30 * 24 * time.Hour) // 30d
	}
	if cfg.Session.IdleTimeout.Duration == 0 {
		cfg.Session.IdleTimeout = NewDuration(7 * 24 * time.Hour) // 7d
	}
	if cfg.Session.TouchThreshold.Duration == 0 {
		cfg.Session.TouchThreshold = NewDuration(1 * time.Minute)
	}
	if cfg.Session.CleanupInterval.Duration == 0 {
		cfg.Session.CleanupInterval = NewDuration(1 * time.Hour)
	}
	if cfg.STS.Enabled && cfg.STS.AssertionMaxAge.Duration == 0 {
		cfg.STS.AssertionMaxAge = NewDuration(5 * time.Minute)
	}
	if cfg.BotVerify != nil && cfg.BotVerify.Enabled {
		if cfg.BotVerify.CodeTTL.Duration == 0 {
			cfg.BotVerify.CodeTTL = NewDuration(5 * time.Minute)
		}
		if cfg.BotVerify.MaxPendingPerIP == 0 {
			cfg.BotVerify.MaxPendingPerIP = 3
		}
	}

	cfg.Health = cfg.Health.WithDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if err := c.TLS.Validate(); err != nil {
		return err
	}
	if err := c.Log.Validate(); err != nil {
		return err
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required")
	}
	if c.OAuth.SessionSecret == "" {
		return fmt.Errorf("oauth.session_secret is required")
	}
	if len(c.OAuth.Providers) == 0 {
		return fmt.Errorf("at least one oauth provider is required")
	}
	for i, p := range c.OAuth.Providers {
		if p.Name == "" {
			return fmt.Errorf("oauth.providers[%d].name is required", i)
		}
		if p.ClientID == "" {
			return fmt.Errorf("oauth.providers[%d].client_id is required", i)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("oauth.providers[%d].client_secret is required", i)
		}
	}
	switch c.JWT.Algorithm {
	case "RS256", "EdDSA":
	default:
		return fmt.Errorf("jwt.algorithm must be RS256 or EdDSA, got %q", c.JWT.Algorithm)
	}

	return nil
}
