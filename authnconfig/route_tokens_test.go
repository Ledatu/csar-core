package authnconfig

import (
	"strings"
	"testing"
	"time"
)

func TestLoadFromBytes_RouteTokensDefaultsAndEnv(t *testing.T) {
	t.Setenv("ROUTE_TOKEN_SECRET", "route-secret")
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://example"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
route_tokens:
  telegram-webapp:
    enabled: true
    secret: "${ROUTE_TOKEN_SECRET}"
    issuer: "csar-authn"
    audience: "telegram-webapp"
    static_claims:
      platform: "telegram"
    claims:
      id:
        source: oauth.telegram.provider_user_id
        as: int
        required: true
      email: user.email
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	profile := cfg.RouteTokens["telegram-webapp"]
	if profile.Algorithm != "HS256" {
		t.Fatalf("Algorithm = %q, want HS256", profile.Algorithm)
	}
	if profile.Secret.Plaintext() != "route-secret" {
		t.Fatal("route token secret was not env-expanded")
	}
	if profile.TTL.Duration != 5*time.Minute {
		t.Fatalf("TTL = %v, want 5m", profile.TTL.Duration)
	}
	if len(profile.Audience) != 1 || profile.Audience[0] != "telegram-webapp" {
		t.Fatalf("Audience = %#v", profile.Audience)
	}
	if profile.Claims["email"].As != RouteTokenClaimString {
		t.Fatalf("email claim As = %q, want string", profile.Claims["email"].As)
	}
}

func TestLoadFromBytes_RouteTokensRequiresSecretWhenEnabled(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://example"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
route_tokens:
  telegram-webapp:
    enabled: true
    claims:
      id: oauth.telegram.provider_user_id
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected missing secret error")
	}
	if !strings.Contains(err.Error(), "route_tokens.telegram-webapp.secret") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadFromBytes_RouteTokensRejectsUnknownSource(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://example"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
route_tokens:
  telegram-webapp:
    enabled: true
    secret: "secret"
    claims:
      id: oauth.telegram.nope
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected unknown source error")
	}
	if !strings.Contains(err.Error(), "unknown source") {
		t.Fatalf("error = %v", err)
	}
}
