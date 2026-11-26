package authnconfig

import (
	"strings"
	"testing"
)

const publicOAuthDeclaration = `  public_oauth:
    version: 1
    enabled: false
    dynamic_clients: true
    authorization_endpoint: https://gateway.example.test/oauth/authorize
    token_endpoint: https://gateway.example.test/oauth/token
    registration_endpoint: https://gateway.example.test/oauth/register
    profiles:
      - profile_id: reports
        resource_aliases: [https://reports.example.test/]
`

func TestPublicOAuthPolicyIsExplicitAndReceiverGated(t *testing.T) {
	body := credentialBase + credentialDeclaration + publicOAuthDeclaration
	cfg, err := LoadFromBytes([]byte(body))
	if err != nil || cfg.Credentials.PublicOAuth == nil || cfg.Credentials.PublicOAuth.Enabled {
		t.Fatal("disabled declaration", err)
	}
	common, declaration := credentialReceiverFixture()
	active := []byte(common + declaration + strings.Replace(publicOAuthDeclaration, "enabled: false", "enabled: true", 1))
	for _, load := range []func([]byte) (*Config, error){LoadFromBytes, LoadFromBytesWithCredentialReceiver, LoadFromBytesWithManualIssuance} {
		if _, err := load(active); err == nil {
			t.Fatal("old receiver activated public OAuth")
		}
	}
	if _, err := LoadFromBytesWithPublicOAuth(active); err != nil {
		t.Fatal("new receiver rejected", err)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown":           func(s string) string { return s + "    quota_namespace: new-budget\n" },
		"version":           func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) },
		"profile":           func(s string) string { return strings.Replace(s, "profile_id: reports", "profile_id: missing", 1) },
		"profile duplicate": func(s string) string { return s + "      - profile_id: reports\n" },
		"resource duplicate": func(s string) string {
			return strings.Replace(s, "resource_aliases: [https://reports.example.test/]", "resource_aliases: [https://reports.example.test]", 1)
		},
		"resource wildcard": func(s string) string {
			return strings.Replace(s, "resource_aliases: [https://reports.example.test/]", "resource_aliases: [https://*.example.test]", 1)
		},
		"endpoint insecure": func(s string) string {
			return strings.Replace(s, "https://gateway.example.test/oauth/token", "http://gateway.example.test/oauth/token", 1)
		},
		"endpoint duplicate": func(s string) string { return strings.Replace(s, "/oauth/token", "/oauth/authorize", 1) },
		"register missing": func(s string) string {
			return strings.Replace(s, "    registration_endpoint: https://gateway.example.test/oauth/register\n", "", 1)
		},
		"register while disabled":   func(s string) string { return strings.Replace(s, "dynamic_clients: true", "dynamic_clients: false", 1) },
		"activation without issuer": func(s string) string { return strings.Replace(s, "enabled: false", "enabled: true", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration + mutate(publicOAuthDeclaration))); err == nil {
				t.Fatal("unsafe public declaration accepted")
			}
		})
	}
}
func TestPublicOAuthResourceCannotSelectAnotherProfile(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration + publicOAuthDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Credentials
	second := c.Profiles[0]
	second.ID = "other"
	second.Audience = "https://other.example.test"
	c.Profiles = append(c.Profiles, second)
	c.PublicOAuth.Profiles = append(c.PublicOAuth.Profiles, CredentialOAuthProfile{ProfileID: "other"})
	if err := c.validate(""); err != nil {
		t.Fatal("two applications rejected", err)
	}
	c.PublicOAuth.Profiles[1].ResourceAliases = []string{c.Profiles[0].Audience}
	if err := c.validate(""); err == nil {
		t.Fatal("resource could select two profile authorities")
	}
}
