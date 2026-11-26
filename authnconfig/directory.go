package authnconfig

import (
	"fmt"
	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BrowserDirectoryConfig selects exact, minimal browser identity projections.
// Login provider enablement never grants directory visibility.
type BrowserDirectoryConfig struct {
	Version     int                          `yaml:"version"`
	Providers   map[string]DirectoryProvider `yaml:"providers,omitempty"`
	Aliases     map[string]string            `yaml:"aliases,omitempty"`
	Projections map[string]string            `yaml:"projections,omitempty"`
}

type DirectoryProvider struct {
	IDFormat            string `yaml:"id_format"` // numeric or opaque
	UsernameMetadataKey string `yaml:"username_metadata_key,omitempty"`
}

func identityName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidIdentityValue bounds opaque source keys and provider IDs without assuming
// an application's numeric-ID convention. It grants no identity authority.
func ValidIdentityValue(s string, maxBytes int) bool {
	return s != "" && len(s) <= maxBytes && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' })
}

func (c *BrowserDirectoryConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.Version != 1 || len(c.Providers) > 16 || len(c.Aliases) > 16 || len(c.Projections) > 16 {
		return fmt.Errorf("browser_directory: invalid version or size")
	}
	for name, p := range c.Providers {
		if !identityName(name) || name == "subject" || name == "email" || name == "phone" || p.IDFormat != "numeric" && p.IDFormat != "opaque" || p.UsernameMetadataKey != "" && !identityName(p.UsernameMetadataKey) {
			return fmt.Errorf("browser_directory: invalid provider")
		}
	}
	for alias, target := range c.Aliases {
		if !identityName(alias) || alias == "subject" || target != "subject" {
			return fmt.Errorf("browser_directory: invalid subject alias")
		}
		if _, exists := c.Providers[alias]; exists {
			return fmt.Errorf("browser_directory: ambiguous alias")
		}
	}
	for name, provider := range c.Projections {
		if !identityName(name) {
			return fmt.Errorf("browser_directory: invalid projection")
		}
		if _, ok := c.Providers[provider]; !ok {
			return fmt.Errorf("browser_directory: projection provider is not allowed")
		}
	}
	return nil
}

// ResolveProvider returns a configured canonical provider; nil is subject-only.
func (c *BrowserDirectoryConfig) ResolveProvider(name string) (string, bool) {
	if name == "" || name == "subject" {
		return "subject", true
	}
	if c == nil {
		return "", false
	}
	if target, ok := c.Aliases[name]; ok {
		return target, true
	}
	_, ok := c.Providers[name]
	return name, ok
}

func (c *BrowserDirectoryConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain BrowserDirectoryConfig
	var decoded plain
	if err := configutil.DecodeStrictYAML(node, &decoded); err != nil {
		return err
	}
	*c = BrowserDirectoryConfig(decoded)
	return nil
}
