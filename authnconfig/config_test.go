package authnconfig

import (
	"strings"
	"testing"
	"time"
)

func TestLoadFromBytes_AuditValidation(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
audit:
  router_base_url: "https://csar:8443/svc/audit"
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for partially configured audit block")
	}
}

func TestLoadFromBytes_HealthAddr(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
health_addr: "127.0.0.1:9181"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	if cfg.ProbeSidecar.Addr != "127.0.0.1:9181" {
		t.Fatalf("ProbeSidecar.Addr = %q, want %q", cfg.ProbeSidecar.Addr, "127.0.0.1:9181")
	}
}

func TestLoadFromBytes_PasskeysDefaultsStateSecret(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
passkeys:
  enabled: true
  rp_id: "auth.example.com"
  rp_display_name: "Auth Example"
  origins:
    - "https://auth.example.com"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	if cfg.Passkeys.StateSecret != "secret" {
		t.Fatalf("Passkeys.StateSecret = %q, want %q", cfg.Passkeys.StateSecret, "secret")
	}
	if cfg.Passkeys.StateCookieName != "csar_passkey_state" {
		t.Fatalf("Passkeys.StateCookieName = %q, want %q", cfg.Passkeys.StateCookieName, "csar_passkey_state")
	}
	if cfg.Passkeys.UserVerification != "required" {
		t.Fatalf("Passkeys.UserVerification = %q, want %q", cfg.Passkeys.UserVerification, "required")
	}
	if cfg.Passkeys.Attestation != "none" {
		t.Fatalf("Passkeys.Attestation = %q, want %q", cfg.Passkeys.Attestation, "none")
	}
}

func TestLoadFromBytes_PasskeysRequireRPID(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
passkeys:
  enabled: true
  rp_display_name: "Auth Example"
  origins:
    - "https://auth.example.com"
`

	if _, err := LoadFromBytes([]byte(yaml)); err == nil {
		t.Fatal("expected error for missing passkeys.rp_id")
	}
}

func TestLoadFromBytes_LegacyTelegramJWTDisabledByDefault(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	if cfg.LegacyLogin.TelegramJWT.Enabled {
		t.Fatal("legacy telegram JWT login should be disabled by default")
	}
}

func TestLoadFromBytes_LegacyTelegramJWTRequiresSecret(t *testing.T) {
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
legacy_login:
  telegram_jwt:
    enabled: true
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing legacy HMAC secret")
	}
	if !strings.Contains(err.Error(), "legacy_login.telegram_jwt.hmac_secret") {
		t.Fatalf("error = %v, want legacy hmac secret validation", err)
	}
}

func TestLoadFromBytes_LegacyTelegramJWTExpandsEnv(t *testing.T) {
	t.Setenv("LEGACY_TELEGRAM_JWT_SECRET", "legacy-secret")
	yaml := `
base_url: "https://auth.example.com"
database:
  dsn: "postgres://test"
oauth:
  session_secret: "secret"
  providers:
    - name: "telegram"
      client_id: "id"
      client_secret: "secret"
legacy_login:
  telegram_jwt:
    enabled: true
    hmac_secret: "${LEGACY_TELEGRAM_JWT_SECRET}"
    issuer: "legacy-auth"
    audience: "legacy-portal"
    max_token_age: "720h"
    endpoint_enabled_until: "2026-08-01T00:00:00Z"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	tg := cfg.LegacyLogin.TelegramJWT
	if !tg.Enabled {
		t.Fatal("legacy telegram JWT login should be enabled")
	}
	if tg.HMACSecret != "legacy-secret" {
		t.Fatalf("HMACSecret = %q, want env-expanded secret", tg.HMACSecret)
	}
	if tg.Issuer != "legacy-auth" || tg.Audience != "legacy-portal" {
		t.Fatalf("unexpected issuer/audience: %q/%q", tg.Issuer, tg.Audience)
	}
	if tg.MaxTokenAge.Duration != 720*time.Hour {
		t.Fatalf("MaxTokenAge = %v, want 720h", tg.MaxTokenAge.Duration)
	}
	if tg.EndpointEnabledUntil.IsZero() {
		t.Fatal("EndpointEnabledUntil should parse from YAML")
	}
}
