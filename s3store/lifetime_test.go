package s3store

import (
	"testing"
	"time"
)

func TestStoredLifetimeCompatibility(t *testing.T) {
	for _, body := range []string{`{"plaintext":"secret"}`, `{"plaintext":"secret","expires_at":"2027-04-04T23:25:08+02:00"}`} {
		obj, err := ParseTokenObject([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if obj.ExpiresAt != nil && obj.ExpiresAt.Location() != time.UTC {
			t.Fatal("expiry not canonical UTC")
		}
		encoded, err := MarshalTokenObject(&obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseTokenObject(encoded); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`{"plaintext":"secret","expires_at":"bad"}`, `{"plaintext":"secret","expires_at":"0001-01-01T00:00:00Z"}`, `{"kind":"oauth2_client_credentials","expires_at":"2027-01-01T00:00:00Z"}`} {
		if _, err := ParseTokenObject([]byte(body)); err == nil {
			t.Fatalf("accepted invalid lifetime: %s", body)
		}
	}
}
