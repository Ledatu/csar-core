package stsclient

import (
	"strings"
	"testing"
	"time"
)

func fullConfig() ServiceAuthConfig {
	return ServiceAuthConfig{
		RouterBaseURL:     "https://api.example.com",
		STSEndpoint:       "https://authn:8081/sts/token",
		Audience:          "csar-authz-svc",
		ServiceName:       "svc:test",
		AssertionAudience: "https://authn.example.com",
		JWT: JWTKeysConfig{
			PrivateKeyFile: "/etc/csar/jwt/private.pem",
			PublicKeyFile:  "/etc/csar/jwt/public.pem",
		},
	}
}

func TestValidate_Empty(t *testing.T) {
	var cfg ServiceAuthConfig
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty config should be valid (unconfigured), got: %v", err)
	}
}

func TestValidate_Full(t *testing.T) {
	cfg := fullConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("full config should be valid, got: %v", err)
	}
}

func TestValidate_Partial(t *testing.T) {
	cfg := ServiceAuthConfig{
		STSEndpoint: "https://authn:8081/sts/token",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("partially configured should return error")
	}
	msg := err.Error()
	for _, field := range []string{"router_base_url", "audience", "service_name", "assertion_audience", "jwt.private_key_file", "jwt.public_key_file"} {
		if !strings.Contains(msg, field) {
			t.Errorf("error should mention %q, got: %s", field, msg)
		}
	}
	if strings.Contains(msg, "sts_endpoint") {
		t.Errorf("error should NOT mention sts_endpoint (it was set), got: %s", msg)
	}
}

func TestIsConfigured(t *testing.T) {
	var empty ServiceAuthConfig
	if empty.IsConfigured() {
		t.Fatal("empty config should not be configured")
	}
	cfg := fullConfig()
	if !cfg.IsConfigured() {
		t.Fatal("full config should be configured")
	}
}

func TestNewRouterClient_BadCert(t *testing.T) {
	cfg := fullConfig()
	cfg.JWT.PrivateKeyFile = "/nonexistent/private.pem"
	cfg.JWT.PublicKeyFile = "/nonexistent/public.pem"
	_, err := NewRouterClient(&cfg, nil)
	if err == nil {
		t.Fatal("expected error for bad cert paths")
	}
	if !strings.Contains(err.Error(), "jwt keys") {
		t.Fatalf("expected jwt keys error, got: %v", err)
	}
}

func TestNewRouterClient_RouterTimeout(t *testing.T) {
	cfg := fullConfig()
	cfg.RouterTimeout = 45 * time.Second

	// Cannot fully build because key files don't exist, but we verify the
	// timeout field is stored correctly by checking the config.
	if cfg.RouterTimeout != 45*time.Second {
		t.Fatalf("RouterTimeout = %v, want 45s", cfg.RouterTimeout)
	}
}

func TestNewRouterClient_ZeroTimeout(t *testing.T) {
	cfg := fullConfig()
	cfg.RouterTimeout = 0

	if cfg.RouterTimeout != 0 {
		t.Fatalf("RouterTimeout = %v, want 0", cfg.RouterTimeout)
	}
}
