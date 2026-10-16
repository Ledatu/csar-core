package jsonredact

import (
	"strings"
	"testing"
)

func TestRedactDiagnosticText(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		secrets     []string
	}{
		{"credentials", `Authorization: Bearer super-secret-access password='private password' api_key=very-secret-key`, []string{"super-secret-access", "private password", "very-secret-key"}},
		{"embedded JSON", `upstream said {"password":"embedded-password", "access_token":"embedded-token"}`, []string{"embedded-password", "embedded-token"}},
		{"cookies", "Cookie: session=private-session; csrf=private-csrf\nrequest failed", []string{"private-session", "private-csrf"}},
		{"url", `database postgres://user:private-password@db.example.com/app unavailable`, []string{"user:private-password"}},
		{"PII", `invalid account person@example.com`, []string{"person@example.com"}},
		{"reflection", `unrecognized opaque-credential`, []string{"opaque-credential"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Only reflection needs known values: the other cases exercise patterns.
			var known []string
			if tc.name == "reflection" {
				known = tc.secrets
			}
			result := RedactText(tc.value, known...)
			for _, secret := range tc.secrets {
				if strings.Contains(result, secret) {
					t.Fatalf("diagnostic leaked credential in %s", tc.name)
				}
			}
			if !strings.Contains(result, DefaultMask) {
				t.Fatal("missing redaction marker")
			}
		})
	}
	if got := RedactText("service temporarily unavailable: try later"); got != "service temporarily unavailable: try later" {
		t.Fatal("changed ordinary diagnostic")
	}
}
