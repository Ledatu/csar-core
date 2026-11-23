package authnconfig

import (
	"strings"
	"testing"
)

func TestOriginRouterCARequiresExplicitVerifiedTLS(t *testing.T) {
	const base = "base_url: https://auth.example.test\ndatabase:\n  dsn: postgres://test\noauth:\n  enabled: false\n"
	for _, tc := range []struct {
		name, settings string
		valid          bool
	}{
		{"legacy disabled", "", true},
		{"plaintext", "origin_router_ca_file: /dedicated-ca.pem\n", false},
		{"no client verification", "origin_router_ca_file: /dedicated-ca.pem\ntls:\n  cert_file: server.pem\n  key_file: server-key.pem\n", false},
		{"verified TLS", "origin_router_ca_file: /dedicated-ca.pem\ntls:\n  cert_file: server.pem\n  key_file: server-key.pem\n  client_ca_file: service-ca.pem\n", true},
		{"whitespace", "origin_router_ca_file: ' private-path.pem '\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(base + tc.settings))
			if (err == nil) != tc.valid {
				t.Fatal("unexpected validation result", err)
			}
			if err != nil && (strings.Contains(err.Error(), "private-path") || strings.Contains(err.Error(), "dedicated-ca.pem")) {
				t.Fatal("validation leaked a configured path")
			}
			if tc.name == "verified TLS" && cfg.OriginRouterCAFile != "/dedicated-ca.pem" {
				t.Fatal("issuer opt-in was discarded")
			}
			if tc.name == "legacy disabled" && cfg.OriginRouterCAFile != "" {
				t.Fatal("legacy config enabled an issuer implicitly")
			}
		})
	}
}
