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

func TestConfiguredOriginPeerIsExactAndHasNoDefault(t *testing.T) {
	const base = "base_url: https://id.example.test\ndatabase: {dsn: postgres://test}\noauth: {enabled: false}\n"
	const trusted = "origin_router_ca_file: /dedicated/router.pem\ntls: {cert_file: server.pem, key_file: key.pem, client_ca_file: general.pem}\n"
	for _, peer := range []string{"reports-router", "unrelated-app-router"} {
		cfg, err := LoadFromBytes([]byte(base + trusted + "origin_router_peer_cn: " + peer + "\n"))
		if err != nil || cfg.OriginRouterPeerCN != peer {
			t.Fatal("configured peer lost", err)
		}
	}
	for _, data := range []string{base + "origin_router_peer_cn: reports-router\n", base + trusted + "origin_router_peer_cn: '*'\n", base + trusted + "origin_router_peer_cn: ' reports-router '\n"} {
		if _, err := LoadFromBytes([]byte(data)); err == nil {
			t.Fatal("ambiguous peer trust accepted")
		}
	}
	cfg, err := LoadFromBytes([]byte(base + trusted))
	if err != nil || cfg.OriginRouterPeerCN != "" {
		t.Fatal("peer was inferred", err)
	}
}
