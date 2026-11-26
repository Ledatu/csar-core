package authnconfig

import (
	"strings"
	"testing"
)

func TestIdentityDirectoryPolicyReceiver(t *testing.T) {
	base := "base_url: https://id.example.test\ndatabase: {dsn: test}\noauth: {enabled: false}\n"
	policy := `browser_directory:
  version: 1
  providers:
    telegram: {id_format: numeric, username_metadata_key: legacy_username}
    example: {id_format: opaque}
  aliases: {aurum: subject}
  projections: {legacy-member: telegram}
`
	cfg, err := LoadFromBytesWithIdentityPolicy([]byte(base + policy))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"subject", "aurum", "telegram", "example"} {
		if _, ok := cfg.BrowserDirectory.ResolveProvider(name); !ok {
			t.Fatal(name)
		}
	}
	if _, ok := (*BrowserDirectoryConfig)(nil).ResolveProvider("telegram"); ok {
		t.Fatal("default directory exposed external identity")
	}
	for _, load := range []func([]byte) (*Config, error){LoadFromBytes, LoadFromBytesWithCredentialReceiver, LoadFromBytesWithManualIssuance, LoadFromBytesWithPublicOAuth} {
		if _, err := load([]byte(base + policy)); err == nil {
			t.Fatal("old reader accepted identity policy")
		}
	}
	for _, bad := range []string{strings.Replace(policy, "version: 1", "version: 2", 1), strings.Replace(policy, "id_format: opaque", "id_format: email", 1), strings.Replace(policy, "example:", "email:", 1), strings.Replace(policy, "aurum: subject", "aurum: telegram", 1), strings.Replace(policy, "legacy-member: telegram", "legacy-member: unknown", 1), strings.Replace(policy, "id_format: opaque", "id_format: opaque, surprise: yes", 1)} {
		if _, err := LoadFromBytesWithIdentityPolicy([]byte(base + bad)); err == nil {
			t.Fatal("invalid directory policy accepted", bad)
		}
	}
}

func TestIdentityImporterPolicy(t *testing.T) {
	p := &IdentityImportConfig{Version: 1, Importers: map[string]IdentityImporter{"source-a": {Subject: "svc:import-a", Source: "app-a", Providers: []string{"external-a"}, MaxUsers: 10, Apply: IdentityImportApply{MaxCreates: 2, MaxLinks: 3}}}}
	cfg := &Config{IdentityImport: p}
	if err := cfg.validateIdentityPolicy(); err != nil {
		t.Fatal(err)
	}
	p.Enabled = true
	if err := cfg.validateIdentityPolicy(); err == nil {
		t.Fatal("import enabled without trusted TLS/outbox/PG")
	}
	p.Enabled = false
	i := p.Importers["source-a"]
	for _, provider := range []string{"email", "phone", "subject", ""} {
		i.Providers = []string{provider}
		p.Importers["source-a"] = i
		if err := cfg.validateIdentityPolicy(); err == nil {
			t.Fatal("unsafe provider admitted")
		}
	}
	i.Providers = []string{"external-a"}
	i.Apply.Enabled = true
	i.Apply.Actions = []string{"create"}
	p.Importers["source-a"] = i
	if err := cfg.validateIdentityPolicy(); err == nil {
		t.Fatal("apply without session-safe lock")
	}
	p.LockDatabaseDSN = "fixture-only"
	if err := cfg.validateIdentityPolicy(); err != nil {
		t.Fatal(err)
	}
	i.Overrides = map[string]string{"key": "00000000-0000-0000-0000-000000000000"}
	p.Importers["source-a"] = i
	if err := cfg.validateIdentityPolicy(); err == nil {
		t.Fatal("nil target override")
	}
}
