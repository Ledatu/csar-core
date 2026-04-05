package authnconfig

import "testing"

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
