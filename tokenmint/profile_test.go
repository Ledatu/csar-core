package tokenmint_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/tokenmint"
)

func baseProfile() tokenmint.Profile {
	return tokenmint.Profile{
		TokenURL:               "https://api-performance.ozon.ru/api/client/token",
		BodyStyle:              tokenmint.BodyStyleJSON,
		AccessTokenPath:        "access_token",
		ExpiresInPath:          "expires_in",
		TokenTypePath:          "token_type",
		ClientIDParam:          "client_id",
		ClientSecretParam:      "client_secret",
		DefaultExpiresIn:       30 * time.Minute,
		ExpiresInHaircut:       0.9,
		RefreshMargin:          5 * time.Minute,
		Timeout:                8 * time.Second,
		MaxResponseBytes:       64 << 10,
		MaxMintsPerMinute:      30,
		SecretRefScopeSegments: 3,
	}
}

func configWith(p *tokenmint.Profile, hosts ...string) *tokenmint.Config {
	if len(hosts) == 0 {
		hosts = []string{"api-performance.ozon.ru"}
	}
	return &tokenmint.Config{
		AllowedHosts: hosts,
		Profiles:     map[string]tokenmint.Profile{"ozon-performance": *p},
	}
}

func TestConfigValidateAcceptsGoodProfile(t *testing.T) {
	base := baseProfile()
	if err := configWith(&base).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestConfigValidateRejectsBadProfiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*tokenmint.Profile)
		hosts  []string
		want   string
	}{
		{
			name:   "non-https token_url",
			mutate: func(p *tokenmint.Profile) { p.TokenURL = "http://api-performance.ozon.ru/api/client/token" },
			want:   "must use https",
		},
		{
			name:   "host not in allowlist",
			mutate: func(p *tokenmint.Profile) { p.TokenURL = "https://evil.example.com/token" },
			want:   "not in allowed_hosts",
		},
		{
			name:   "unknown body style",
			mutate: func(p *tokenmint.Profile) { p.BodyStyle = "xml" },
			want:   "body_style",
		},
		{
			name:   "haircut above one",
			mutate: func(p *tokenmint.Profile) { p.ExpiresInHaircut = 1.5 },
			want:   "expires_in_haircut",
		},
		{
			name:   "refresh margin swallows the lifetime",
			mutate: func(p *tokenmint.Profile) { p.RefreshMargin = time.Hour },
			want:   "refresh_margin",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := baseProfile()
			tc.mutate(&p)
			err := configWith(&p, tc.hosts...).Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Validate applies defaults, so a Config assembled in Go behaves the same as
// one loaded from YAML. Zero means "unset", not "invalid".
func TestConfigValidateFillsUnsetFields(t *testing.T) {
	p := baseProfile()
	p.Timeout = 0
	p.SecretRefScopeSegments = 0
	p.ExpiresInHaircut = 0
	p.IdleTTL = 0
	p.MaxMintsPerMinute = 0

	cfg := configWith(&p)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	got, ok := cfg.Profile("ozon-performance")
	if !ok {
		t.Fatal("profile missing")
	}
	if got.Timeout <= 0 {
		t.Errorf("Timeout = %v, want a default", got.Timeout)
	}
	if got.SecretRefScopeSegments != 3 {
		t.Errorf("SecretRefScopeSegments = %d, want 3", got.SecretRefScopeSegments)
	}
	if got.ExpiresInHaircut <= 0 || got.ExpiresInHaircut > 1 {
		t.Errorf("ExpiresInHaircut = %v, want a default in (0,1]", got.ExpiresInHaircut)
	}
	if got.IdleTTL <= 0 || got.MaxMintsPerMinute <= 0 {
		t.Errorf("IdleTTL=%v MaxMintsPerMinute=%v, want defaults", got.IdleTTL, got.MaxMintsPerMinute)
	}
}

func TestConfigValidateRejectsEmptyProfiles(t *testing.T) {
	cfg := &tokenmint.Config{AllowedHosts: []string{"example.com"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a config with no profiles")
	}
}

func TestConfigAllowPrivatePermitsPlainHTTP(t *testing.T) {
	p := baseProfile()
	p.TokenURL = "http://mockapi:9999/api/client/token"
	cfg := &tokenmint.Config{
		AllowedHosts: []string{"mockapi"},
		AllowPrivate: true,
		Profiles:     map[string]tokenmint.Profile{"dev": p},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate with allow_private: %v", err)
	}
}

func TestLoadConfigFileAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokenmint.yaml")
	body := `
allowed_hosts: ["api-performance.ozon.ru"]
profiles:
  ozon-performance:
    token_url: "https://api-performance.ozon.ru/api/client/token"
    static_params:
      grant_type: "client_credentials"
    expected_token_type: "Bearer"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := tokenmint.LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}

	p, ok := cfg.Profile("ozon-performance")
	if !ok {
		t.Fatal("profile not found")
	}
	if p.BodyStyle != tokenmint.BodyStyleJSON {
		t.Errorf("BodyStyle = %q, want json by default", p.BodyStyle)
	}
	if p.AccessTokenPath != "access_token" {
		t.Errorf("AccessTokenPath = %q, want access_token", p.AccessTokenPath)
	}
	if p.SecretRefScopeSegments != 3 {
		t.Errorf("SecretRefScopeSegments = %d, want 3", p.SecretRefScopeSegments)
	}
	if p.Timeout <= 0 || p.MaxMintsPerMinute <= 0 {
		t.Errorf("defaults not applied: timeout=%v rate=%v", p.Timeout, p.MaxMintsPerMinute)
	}
	if !cfg.HostAllowed("API-Performance.Ozon.RU") {
		t.Error("HostAllowed should be case-insensitive")
	}
	if cfg.HostAllowed("evil.example.com") {
		t.Error("HostAllowed accepted a host outside the allowlist")
	}
}

func TestLoadConfigFileRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	body := `
allowed_hosts: ["api-performance.ozon.ru"]
profiles:
  broken:
    token_url: "https://somewhere-else.example.com/token"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := tokenmint.LoadConfigFile(path); err == nil {
		t.Fatal("LoadConfigFile accepted a token_url outside allowed_hosts")
	}
}

func TestDescriptorValidate(t *testing.T) {
	good := tokenmint.Descriptor{
		Kind:            tokenmint.KindOAuth2ClientCredentials,
		GrantProfile:    "ozon-performance",
		ClientIDRef:     "accounts/ozon/123/performance/client_id",
		ClientSecretRef: "accounts/ozon/123/performance/client_secret",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*tokenmint.Descriptor)
	}{
		{"unknown kind", func(d *tokenmint.Descriptor) { d.Kind = "saml_assertion" }},
		{"empty kind", func(d *tokenmint.Descriptor) { d.Kind = "" }},
		{"no profile", func(d *tokenmint.Descriptor) { d.GrantProfile = "" }},
		{"no client id ref", func(d *tokenmint.Descriptor) { d.ClientIDRef = "" }},
		{"no client secret ref", func(d *tokenmint.Descriptor) { d.ClientSecretRef = "" }},
		{"identical refs", func(d *tokenmint.Descriptor) { d.ClientSecretRef = d.ClientIDRef }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := good
			tc.mutate(&d)
			if err := d.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", tc.name)
			}
		})
	}
}

func TestDescriptorUnknownKindIsIdentifiable(t *testing.T) {
	d := tokenmint.Descriptor{
		Kind:            "saml_assertion",
		GrantProfile:    "p",
		ClientIDRef:     "a",
		ClientSecretRef: "b",
	}
	if err := d.Validate(); !errors.Is(err, tokenmint.ErrUnknownKind) {
		t.Fatalf("err = %v, want ErrUnknownKind", err)
	}
}
