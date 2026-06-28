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

func TestLoadFromBytes_EmailOTPDisabledByDefault(t *testing.T) {
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
	if cfg.EmailOTP != nil && cfg.EmailOTP.Enabled {
		t.Fatal("email OTP should be disabled by default")
	}
}

func TestLoadFromBytes_EmailOTPDefaults(t *testing.T) {
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
email_otp:
  enabled: true
  sender_address: "login@example.com"
  postbox:
    auth:
      auth_mode: "metadata"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	if cfg.EmailOTP.CodeTTL.Duration != 5*time.Minute {
		t.Fatalf("EmailOTP.CodeTTL = %v, want 5m", cfg.EmailOTP.CodeTTL.Duration)
	}
	if cfg.EmailOTP.MaxPendingPerIP != 3 {
		t.Fatalf("EmailOTP.MaxPendingPerIP = %d, want 3", cfg.EmailOTP.MaxPendingPerIP)
	}
	if cfg.EmailOTP.MaxPendingPerEmail != 3 {
		t.Fatalf("EmailOTP.MaxPendingPerEmail = %d, want 3", cfg.EmailOTP.MaxPendingPerEmail)
	}
	if cfg.EmailOTP.MaxAttempts != 5 {
		t.Fatalf("EmailOTP.MaxAttempts = %d, want 5", cfg.EmailOTP.MaxAttempts)
	}
	if cfg.EmailOTP.Cooldown.Duration != time.Minute {
		t.Fatalf("EmailOTP.Cooldown = %v, want 1m", cfg.EmailOTP.Cooldown.Duration)
	}
	if cfg.EmailOTP.Postbox.Endpoint != "https://postbox.cloud.yandex.net" {
		t.Fatalf("EmailOTP.Postbox.Endpoint = %q", cfg.EmailOTP.Postbox.Endpoint)
	}
	if cfg.EmailOTP.Postbox.Region != "ru-central1" {
		t.Fatalf("EmailOTP.Postbox.Region = %q", cfg.EmailOTP.Postbox.Region)
	}
	if cfg.EmailOTP.Subject == "" {
		t.Fatal("EmailOTP.Subject should default")
	}
}

func TestLoadFromBytes_EmailOTPRequiresSender(t *testing.T) {
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
email_otp:
  enabled: true
  postbox:
    auth:
      auth_mode: "metadata"
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing email_otp.sender_address")
	}
	if !strings.Contains(err.Error(), "email_otp.sender_address") {
		t.Fatalf("error = %v, want sender validation", err)
	}
}

func TestLoadFromBytes_EmailOTPRequiresAuthMode(t *testing.T) {
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
email_otp:
  enabled: true
  sender_address: "login@example.com"
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing postbox auth mode")
	}
	if !strings.Contains(err.Error(), "email_otp.postbox.auth.auth_mode") {
		t.Fatalf("error = %v, want auth mode validation", err)
	}
}

func TestLoadFromBytes_EmailOTPExpandsEnv(t *testing.T) {
	t.Setenv("EMAIL_OTP_FROM_ADDRESS", "login@example.com")
	t.Setenv("YANDEX_POSTBOX_SA_KEY_FILE", "/run/secrets/yandex-sa.json")
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
email_otp:
  enabled: true
  sender_address: "${EMAIL_OTP_FROM_ADDRESS}"
  postbox:
    auth:
      auth_mode: "service_account"
      sa_key_file: "${YANDEX_POSTBOX_SA_KEY_FILE}"
`

	cfg, err := LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes() error = %v", err)
	}
	if cfg.EmailOTP.SenderAddress != "login@example.com" {
		t.Fatalf("SenderAddress = %q, want env-expanded address", cfg.EmailOTP.SenderAddress)
	}
	if cfg.EmailOTP.Postbox.Auth.SAKeyFile != "/run/secrets/yandex-sa.json" {
		t.Fatalf("SAKeyFile = %q, want env-expanded path", cfg.EmailOTP.Postbox.Auth.SAKeyFile)
	}
}

func TestLoadFromBytes_EmailOTPRejectsInvalidLimits(t *testing.T) {
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
email_otp:
  enabled: true
  code_ttl: "-1s"
  sender_address: "login@example.com"
  postbox:
    auth:
      auth_mode: "metadata"
`

	_, err := LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid email OTP TTL")
	}
	if !strings.Contains(err.Error(), "email_otp.code_ttl") {
		t.Fatalf("error = %v, want ttl validation", err)
	}
}
