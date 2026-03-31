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
