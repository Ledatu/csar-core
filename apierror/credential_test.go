package apierror

import (
	"strings"
	"testing"
)

func TestCredentialFailureCodeIsBoundedAndAllowlisted(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"status":502,"code":"credential_invalid","message":"untrusted reflected content"}`, CodeCredentialInvalid},
		{`{"status":502,"code":"credential_throttled"}`, CodeCredentialThrottled},
		{`{"status":401,"code":"credential_invalid"}`, ""},
		{`{"status":502,"code":"invented"}`, ""},
		{`{"status":502,"code":"credential_invalid"`, ""},
		{strings.Repeat(" ", 4097), ""},
	} {
		if got := CredentialFailureCode([]byte(tc.body)); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}
