package authnconfig

import (
	"fmt"
	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
	"strings"

	"github.com/google/uuid"
)

// IdentityImportConfig is a separate, opt-in authority to attest imported links.
// Its session-safe lock keeps the existing physical importer lock identity.
type IdentityImportConfig struct {
	Version         int                         `yaml:"version"`
	Enabled         bool                        `yaml:"enabled"`
	RouterPeerCN    string                      `yaml:"router_peer_cn"`
	LockDatabaseDSN string                      `yaml:"lock_database_dsn,omitempty"`
	Importers       map[string]IdentityImporter `yaml:"importers"`
}
type IdentityImporter struct {
	Subject   string              `yaml:"subject"`
	Source    string              `yaml:"source"`
	Providers []string            `yaml:"providers"`
	MaxUsers  int                 `yaml:"max_users"`
	Apply     IdentityImportApply `yaml:"apply"`
	Overrides map[string]string   `yaml:"overrides,omitempty"`
}
type IdentityImportApply struct {
	Enabled    bool     `yaml:"enabled"`
	Actions    []string `yaml:"actions,omitempty"`
	MaxLinks   int      `yaml:"max_links"`
	MaxCreates int      `yaml:"max_creates"`
}

func (c *Config) validateIdentityPolicy() error {
	if err := c.BrowserDirectory.validate(); err != nil {
		return err
	}
	p := c.IdentityImport
	if p == nil {
		return nil
	}
	if p.Version != 1 || len(p.Importers) > 32 || p.Enabled && len(p.Importers) == 0 {
		return fmt.Errorf("identity_import: invalid version or importer count")
	}
	if p.Enabled && (c.Database.Driver != "postgres" || !c.AuditOutboxEnabled || !c.TLS.IsEnabled() || c.TLS.ClientCAFile == "" || !identityName(p.RouterPeerCN)) {
		return fmt.Errorf("identity_import: PostgreSQL, transactional audit and verified client TLS are required")
	}
	if c.LegacyUsersSync.Enabled && p.Enabled && c.LegacyUsersSync.LockDatabaseDSN != "" && p.LockDatabaseDSN != "" && c.LegacyUsersSync.LockDatabaseDSN != p.LockDatabaseDSN {
		return fmt.Errorf("identity_import: old and new importers require the same lock endpoint")
	}
	for name, i := range p.Importers {
		if !identityName(name) || !strings.HasPrefix(i.Subject, "svc:") || !identityName(strings.TrimPrefix(i.Subject, "svc:")) || !ValidIdentityValue(i.Source, 128) || len(i.Providers) < 1 || len(i.Providers) > 16 || i.MaxUsers < 1 || i.MaxUsers > 20000 || len(i.Overrides) > 20000 {
			return fmt.Errorf("identity_import: invalid importer binding or bounds")
		}
		seen := map[string]bool{}
		for _, provider := range i.Providers {
			if !identityName(provider) || provider == "subject" || provider == "email" || provider == "phone" || seen[provider] {
				return fmt.Errorf("identity_import: invalid provider authority")
			}
			seen[provider] = true
		}
		a := i.Apply
		if a.MaxLinks < 0 || a.MaxLinks > i.MaxUsers || a.MaxCreates < 0 || a.MaxCreates > i.MaxUsers || a.Enabled && (len(a.Actions) == 0 || p.LockDatabaseDSN == "") {
			return fmt.Errorf("identity_import: invalid apply bounds or missing session-safe lock endpoint")
		}
		seen = map[string]bool{}
		for _, action := range a.Actions {
			if action != "create" && action != "link" || seen[action] || action == "create" && a.MaxCreates == 0 || action == "link" && a.MaxLinks == 0 {
				return fmt.Errorf("identity_import: invalid apply action")
			}
			seen[action] = true
		}
		for key, target := range i.Overrides {
			id, err := uuid.Parse(target)
			if !ValidIdentityValue(key, 128) || err != nil || id == uuid.Nil {
				return fmt.Errorf("identity_import: invalid configured override")
			}
		}
	}
	return nil
}

func (c *IdentityImportConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain IdentityImportConfig
	var decoded plain
	if err := configutil.DecodeStrictYAML(node, &decoded); err != nil {
		return err
	}
	*c = IdentityImportConfig(decoded)
	return nil
}
