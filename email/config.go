// Package email provides shared outbound email transports. Business templates,
// recipient ownership and retry policies belong to the consuming service.
package email

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar-core/postbox"
	"github.com/ledatu/csar-core/secret"
)

const (
	ProviderPostbox  = "postbox"
	ProviderSelectel = "selectel"
	TLSImplicit      = "tls"
	TLSStartTLS      = "starttls"
	SelectelHost     = "smtp.mail.selcloud.ru"
)

// Config selects exactly one transport. Omitted provider sections stay inactive.
type Config struct {
	Provider string          `yaml:"provider"`
	Postbox  *postbox.Config `yaml:"postbox,omitempty"`
	Selectel *SMTPConfig     `yaml:"selectel,omitempty"`
}

// SMTPConfig describes authenticated submission with required, verified TLS.
type SMTPConfig struct {
	Host     string              `yaml:"host"`
	Port     int                 `yaml:"port"`
	TLSMode  string              `yaml:"tls_mode"`
	Username string              `yaml:"username"`
	Password secret.Secret       `yaml:"password"`
	Timeout  configutil.Duration `yaml:"timeout"`
}

// ApplyDefaults fills only the selected provider's settings.
func (c *Config) ApplyDefaults() {
	switch c.Provider {
	case ProviderPostbox:
		if c.Postbox != nil {
			c.Postbox.ApplyDefaults()
		}
	case ProviderSelectel:
		if c.Selectel != nil {
			if c.Selectel.Host == "" {
				c.Selectel.Host = SelectelHost
			}
			if c.Selectel.TLSMode == "" {
				c.Selectel.TLSMode = TLSImplicit
			}
			if c.Selectel.Port == 0 {
				c.Selectel.Port = 1127
				if c.Selectel.TLSMode == TLSStartTLS {
					c.Selectel.Port = 1126
				}
			}
			if c.Selectel.Timeout.Duration == 0 {
				c.Selectel.Timeout = configutil.Duration{Duration: 10 * time.Second}
			}
		}
	}
}

// Validate checks config without connecting or opening credential files.
func (c Config) Validate(prefix string) error {
	switch c.Provider {
	case ProviderPostbox:
		if c.Postbox == nil || c.Selectel != nil {
			return fmt.Errorf("%s requires only the postbox section", prefix)
		}
		endpoint, err := url.Parse(c.Postbox.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return fmt.Errorf("%s.postbox.endpoint must be an HTTPS URL without credentials, query or fragment", prefix)
		}
		return c.Postbox.Validate(prefix + ".postbox")
	case ProviderSelectel:
		if c.Selectel == nil || c.Postbox != nil {
			return fmt.Errorf("%s requires only the selectel section", prefix)
		}
		return c.Selectel.validate(prefix + ".selectel")
	default:
		return fmt.Errorf("%s.provider must be postbox or selectel", prefix)
	}
}

func (c *SMTPConfig) validate(prefix string) error {
	if c.Host == "" || strings.ContainsAny(c.Host, "\r\n\t\x00 /@") || net.ParseIP(c.Host) == nil && strings.Contains(c.Host, ":") {
		return fmt.Errorf("%s.host must be a hostname or IP without a port", prefix)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%s.port must be between 1 and 65535", prefix)
	}
	if c.TLSMode != TLSImplicit && c.TLSMode != TLSStartTLS {
		return fmt.Errorf("%s.tls_mode must be tls or starttls", prefix)
	}
	if c.Username == "" || strings.ContainsAny(c.Username, "\r\n\x00") || c.Password.IsEmpty() {
		return fmt.Errorf("%s requires username and password", prefix)
	}
	if c.Timeout.Duration <= 0 || c.Timeout.Duration > time.Minute {
		return fmt.Errorf("%s.timeout must be greater than zero and at most 1m", prefix)
	}
	return nil
}
