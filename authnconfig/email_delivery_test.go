package authnconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/email"
)

func TestEmailOTPSelectelDefaultsAndSecretExpansion(t *testing.T) {
	t.Setenv("SELECTEL_SMTP_PASSWORD", "test-selectel-password")
	cfg, err := LoadFromBytes([]byte(legacyUsersSyncBaseYAML + `
email_otp:
  enabled: true
  sender_address: login@example.com
  delivery:
    provider: selectel
    selectel:
      username: test-user
      password: "${SELECTEL_SMTP_PASSWORD}"
`))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.EmailOTP.EmailDelivery()
	if d.Provider != email.ProviderSelectel || d.Selectel.Host != email.SelectelHost || d.Selectel.Port != 1127 || d.Selectel.TLSMode != email.TLSImplicit || d.Selectel.Timeout.Duration != 10*time.Second {
		t.Fatal("Selectel defaults not applied")
	}
	if d.Selectel.Password.Plaintext() != "test-selectel-password" || strings.Contains(d.Selectel.Password.String(), "test-selectel-password") {
		t.Fatal("password expansion/redaction failed")
	}
	if cfg.EmailOTP.Postbox.Endpoint != "" {
		t.Fatal("unused Postbox defaults applied")
	}
}

func TestEmailOTPDeliveryValidation(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"starttls", `delivery: {provider: selectel, selectel: {username: user, password: pass, tls_mode: starttls}}`, ""},
		{"explicit postbox", `delivery: {provider: postbox, postbox: {auth: {auth_mode: metadata}}}`, ""},
		{"missing password", `delivery: {provider: selectel, selectel: {username: user}}`, "username and password"},
		{"insecure postbox", `delivery: {provider: postbox, postbox: {endpoint: http://example.com, auth: {auth_mode: metadata}}}`, "HTTPS"},
		{"plaintext", `delivery: {provider: selectel, selectel: {username: user, password: pass, tls_mode: none}}`, "tls_mode"},
		{"negative timeout", `delivery: {provider: selectel, selectel: {username: user, password: pass, timeout: '-1s'}}`, "timeout"},
		{"excessive timeout", `delivery: {provider: selectel, selectel: {username: user, password: pass, timeout: '2m'}}`, "timeout"},
		{"invalid port", `delivery: {provider: selectel, selectel: {username: user, password: pass, port: 65536}}`, "port"},
		{"host injection", `delivery: {provider: selectel, selectel: {username: user, password: pass, host: 'smtp.example.com:25'}}`, "host"},
		{"unknown provider", `delivery: {provider: other}`, "provider"},
		{"mixed sections", `delivery: {provider: selectel, postbox: {}, selectel: {username: user, password: pass}}`, "only the selectel"},
		{"legacy conflict", "postbox: {auth: {auth_mode: metadata}}\n  delivery: {provider: selectel, selectel: {username: user, password: pass}}", "cannot both"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(legacyUsersSyncBaseYAML + "\nemail_otp:\n  enabled: true\n  sender_address: login@example.com\n  " + tt.body + "\n"))
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("expected %s, got %v", tt.want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.name == "starttls" && cfg.EmailOTP.Delivery.Selectel.Port != 1126 {
				t.Fatal("wrong STARTTLS port")
			}
		})
	}
}

func TestEmailOTPLegacyDeliveryCompatibility(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(legacyUsersSyncBaseYAML + `
email_otp:
  enabled: true
  sender_address: login@example.com
  postbox:
    auth: {auth_mode: metadata}
`))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.EmailOTP.EmailDelivery()
	if d.Provider != email.ProviderPostbox || d.Postbox == nil || d.Postbox.Auth.AuthMode != "metadata" {
		t.Fatal("legacy provider changed")
	}
}

func TestEmailOTPLegacyPostboxURLValidation(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://example.com?token=secret", "https://user:secret@example.com", "https://example.com#fragment"} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(legacyUsersSyncBaseYAML + `
email_otp:
  enabled: true
  sender_address: login@example.com
  postbox:
    endpoint: "` + endpoint + `"
    auth: {auth_mode: metadata}
`))
			if err == nil || !strings.Contains(err.Error(), "HTTPS") {
				t.Fatalf("expected endpoint rejection during config load, got %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("endpoint credentials leaked")
			}
		})
	}
}
