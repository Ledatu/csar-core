package authnconfig

import (
	"strings"
	"testing"
)

func TestOAuthDisabledDoesNotRequireProviderCredentials(t *testing.T) {
	cfg, err := LoadFromBytes([]byte("base_url: https://example.com\ndatabase:\n  dsn: postgres://localhost/authn\noauth:\n  enabled: false\n"))
	if err != nil {
		t.Fatalf("disabled OAuth config: %v", err)
	}
	if cfg.OAuth.IsEnabled() {
		t.Fatal("OAuth must be disabled")
	}
}

func TestOAuthEnabledDefaultsPreserveProviderRequirements(t *testing.T) {
	for _, setting := range []string{"", "  enabled: true\n"} {
		_, err := LoadFromBytes([]byte("base_url: https://example.com\ndatabase:\n  dsn: postgres://localhost/authn\noauth:\n" + setting + "  session_secret: test-secret\n"))
		if err == nil || !strings.Contains(err.Error(), "at least one oauth provider") {
			t.Fatalf("setting %q: expected provider validation, got %v", setting, err)
		}
	}
}
