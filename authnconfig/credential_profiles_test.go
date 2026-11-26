package authnconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ledatu/csar-core/authntokens"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const credentialBase = "base_url: https://id.example.test\ndatabase:\n  dsn: postgres://test\noauth:\n  enabled: false\n"

const credentialDeclaration = `credentials:
  version: 1
  enabled: false
  issuer_url: https://id.example.test
  consent_url: https://console.example.test/consent
  mutation_origins: [https://console.example.test]
  consent_cookie_name: __Host-reports-consent
  trust_policies:
    - id: reports-ingress
      ca_file: /dedicated/reports-ca.pem
      peer_cn: reports-router
  profiles:
    - id: reports
      revision: 1
      audience: https://reports.example.test
      scopes: [{scope: 'reports:read', decision_profile: report-reader}]
      namespaces: [workspace]
      selection_modes: [selected, current_and_future]
      access_ttl: 1h
      grant_ttl: 168h
      proof_ttl: 1m
      trust_policy: reports-ingress
  receivers:
    - subject: svc:resource-owner
      profiles: [reports]
      operations: [inspect, evaluate]
      trust_policy: reports-ingress
`

func TestCredentialDeclarationsAreDisabled(t *testing.T) {
	absent, err := LoadFromBytes([]byte(credentialBase))
	if err != nil || absent.Credentials != nil {
		t.Fatal("absent declaration changed defaults", err)
	}
	for name, declaration := range map[string]string{
		"unrelated application": credentialDeclaration,
		"Aurum deployment data": strings.NewReplacer("reports.example.test", "mcp.aurum-sky.net", "reports:read", "analytics:read", "workspace", "wildberries", "svc:resource-owner", "svc:aurumskynet-campaigns").Replace(credentialDeclaration),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(credentialBase + declaration))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Credentials.Enabled || cfg.RouteTokens != nil || cfg.Redis != nil || cfg.Cookie.Name != "csar_session" {
				t.Fatal("declaration activated or changed legacy behavior")
			}
			if cfg.Credentials.Profiles[0].Revision != 1 || cfg.Credentials.Receivers[0].Subject == "" {
				t.Fatal("declaration was discarded")
			}
		})
	}
	_, err = LoadFromBytes([]byte(credentialBase + strings.Replace(credentialDeclaration, "enabled: false", "enabled: true", 1)))
	if err == nil || !strings.Contains(err.Error(), "runtime activation is not supported") {
		t.Fatal("unsupported activation accepted", err)
	}
}

func TestCredentialDeclarationFailures(t *testing.T) {
	for name, change := range map[string]func(string) string{
		"unknown version":      func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) },
		"missing version":      func(s string) string { return strings.Replace(s, "  version: 1\n", "", 1) },
		"unknown field":        func(s string) string { return s + "  enable: true\n" },
		"nested unknown field": func(s string) string { return strings.Replace(s, "revision: 1", "revision: 1\n      extra: true", 1) },
		"duplicate field":      func(s string) string { return strings.Replace(s, "version: 1", "version: 1\n  version: 1", 1) },
		"null block":           func(string) string { return "credentials: null\n" },
		"empty block":          func(string) string { return "credentials: {}\n" },
		"nonmapping block":     func(string) string { return "credentials: []\n" },
		"null profile": func(s string) string {
			return strings.Replace(s, "    - id: reports\n", "    - null\n    - id: reports\n", 1)
		},
		"second document":             func(s string) string { return s + "---\ncredentials: {}\n" },
		"malformed trailing document": func(s string) string { return s + "---\ninvalid: [\n" },
		"wildcard origin": func(s string) string {
			return strings.ReplaceAll(s, "https://console.example.test]", "https://*.example.test]")
		},
		"origin path": func(s string) string {
			return strings.Replace(s, "mutation_origins: [https://console.example.test]", "mutation_origins: [https://console.example.test/]", 1)
		},
		"duplicate origin": func(s string) string {
			return strings.Replace(s, "mutation_origins: [https://console.example.test]", "mutation_origins: [https://console.example.test, https://console.example.test]", 1)
		},
		"missing origin": func(s string) string {
			return strings.Replace(s, "mutation_origins: [https://console.example.test]", "mutation_origins: []", 1)
		},
		"insecure cookie": func(s string) string { return strings.Replace(s, "__Host-reports-consent", "reports-consent", 1) },
		"issuer query": func(s string) string {
			return strings.Replace(s, "issuer_url: https://id.example.test", "issuer_url: https://id.example.test?secret=do-not-echo", 1)
		},
		"unknown trust": func(s string) string {
			return strings.Replace(s, "trust_policy: reports-ingress", "trust_policy: unknown", 1)
		},
		"zero revision": func(s string) string { return strings.Replace(s, "revision: 1", "revision: 0", 1) },
		"namespace duplicate": func(s string) string {
			return strings.Replace(s, "namespaces: [workspace]", "namespaces: [workspace, workspace]", 1)
		},
		"bad decision reference": func(s string) string {
			return strings.Replace(s, "decision_profile: report-reader", "decision_profile: '*'", 1)
		},
		"scope duplicate": func(s string) string {
			return strings.Replace(s, "scopes: [{scope: 'reports:read', decision_profile: report-reader}]", "scopes: [{scope: 'reports:read', decision_profile: report-reader}, {scope: 'reports:read', decision_profile: report-reader}]", 1)
		},
		"scope missing": func(s string) string {
			return strings.Replace(s, "scopes: [{scope: 'reports:read', decision_profile: report-reader}]", "scopes: []", 1)
		},
		"mixed modes": func(s string) string { return strings.Replace(s, "selected, current_and_future", "selected, all", 1) },
		"mode duplicate": func(s string) string {
			return strings.Replace(s, "selected, current_and_future", "selected, selected", 1)
		},
		"zero TTL":                 func(s string) string { return strings.Replace(s, "access_ttl: 1h", "access_ttl: 0s", 1) },
		"access beyond grant":      func(s string) string { return strings.Replace(s, "access_ttl: 1h", "access_ttl: 169h", 1) },
		"proof beyond access":      func(s string) string { return strings.Replace(s, "proof_ttl: 1m", "proof_ttl: 2h", 1) },
		"invalid duration":         func(s string) string { return strings.Replace(s, "proof_ttl: 1m", "proof_ttl: secret-do-not-echo", 1) },
		"wildcard service":         func(s string) string { return strings.Replace(s, "svc:resource-owner", "svc:*", 1) },
		"service prefix only":      func(s string) string { return strings.Replace(s, "svc:resource-owner", "'svc:'", 1) },
		"nonservice receiver":      func(s string) string { return strings.Replace(s, "svc:resource-owner", "owner", 1) },
		"unknown receiver profile": func(s string) string { return strings.Replace(s, "profiles: [reports]", "profiles: [unknown]", 1) },
		"duplicate receiver profile": func(s string) string {
			return strings.Replace(s, "profiles: [reports]", "profiles: [reports, reports]", 1)
		},
		"issuance capability":     func(s string) string { return strings.Replace(s, "inspect, evaluate", "inspect, issue", 1) },
		"duplicate operation":     func(s string) string { return strings.Replace(s, "inspect, evaluate", "inspect, inspect", 1) },
		"unverified peer pattern": func(s string) string { return strings.Replace(s, "peer_cn: reports-router", "peer_cn: '*'", 1) },
		"relative CA":             func(s string) string { return strings.Replace(s, "/dedicated/reports-ca.pem", "relative.pem", 1) },
		"CA with dot segments": func(s string) string {
			return strings.Replace(s, "/dedicated/reports-ca.pem", "/dedicated/../secret-do-not-echo.pem", 1)
		},
		"section alias": func(s string) string {
			return "defaults: &defaults\n" + strings.TrimPrefix(s, "credentials:\n") + "credentials: *defaults\n"
		},
		"root merge": func(s string) string { return "defaults: &defaults\n  harmless: true\n<<: *defaults\n" + s },
		"inner alias": func(s string) string {
			return strings.Replace(s, "namespaces: [workspace]", "namespaces: &shared [workspace]", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(credentialBase + change(credentialDeclaration)))
			if err == nil {
				t.Fatal("unsafe declaration accepted")
			}
			if strings.Contains(err.Error(), "do-not-echo") {
				t.Fatal("configured value leaked in error")
			}
		})
	}
}

func TestCredentialCollectionBoundsAndReferences(t *testing.T) {
	for name, mutate := range map[string]func(*CredentialConfig){
		"duplicate profile":       func(c *CredentialConfig) { c.Profiles = append(c.Profiles, c.Profiles[0]) },
		"duplicate trust":         func(c *CredentialConfig) { c.TrustPolicies = append(c.TrustPolicies, c.TrustPolicies[0]) },
		"duplicate receiver":      func(c *CredentialConfig) { c.Receivers = append(c.Receivers, c.Receivers[0]) },
		"unknown receiver trust":  func(c *CredentialConfig) { c.Receivers[0].TrustPolicy = "missing" },
		"too many profiles":       func(c *CredentialConfig) { c.Profiles = slices.Repeat(c.Profiles, 33) },
		"too many trust policies": func(c *CredentialConfig) { c.TrustPolicies = slices.Repeat(c.TrustPolicies, 33) },
		"too many receivers":      func(c *CredentialConfig) { c.Receivers = slices.Repeat(c.Receivers, 65) },
		"too many origins":        func(c *CredentialConfig) { c.MutationOrigins = slices.Repeat(c.MutationOrigins, 33) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration))
			if err != nil {
				t.Fatal(err)
			}
			mutate(cfg.Credentials)
			if cfg.Credentials.validate("") == nil {
				t.Fatal("unsafe collection accepted")
			}
		})
	}
	cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.validate("/dedicated/reports-ca.pem") == nil {
		t.Fatal("general service root reused as dedicated trust")
	}
	// The same CA path in two named policies must not combine their peer identities.
	cfg.Credentials.TrustPolicies = append(cfg.Credentials.TrustPolicies, CredentialTrustPolicy{ID: "other-feature", CAFile: "/dedicated/reports-ca.pem", PeerCN: "different-router"})
	if err := cfg.Credentials.validate(""); err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.Profiles[0].TrustPolicy != "reports-ingress" || cfg.Credentials.TrustPolicies[0].PeerCN != "reports-router" {
		t.Fatal("feature trust was broadened")
	}
}

func TestCredentialEnvironmentExpansion(t *testing.T) {
	t.Setenv("CSAR_TEST_PROFILE_TTL", "2h")
	t.Setenv("CSAR_TEST_PROFILE_ISSUER", "https://id.example.test\ncredentials: {enabled: true}")
	data := strings.Replace(credentialDeclaration, "access_ttl: 1h", "access_ttl: '${CSAR_TEST_PROFILE_TTL}'", 1)
	cfg, err := LoadFromBytes([]byte(credentialBase + data))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.Profiles[0].AccessTTL.String() != "2h0m0s" {
		t.Fatal("typed duration expansion failed")
	}
	data = strings.Replace(credentialDeclaration, "issuer_url: https://id.example.test", "issuer_url: '${CSAR_TEST_PROFILE_ISSUER}'", 1)
	if _, err = LoadFromBytes([]byte(credentialBase + data)); err == nil {
		t.Fatal("expanded YAML injection accepted")
	}
	// Config round-trip still treats each configured scope as a literal string.
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = LoadFromBytes(body); err != nil {
		t.Fatal(fmt.Errorf("round-trip declaration: %w", err))
	}
}

func TestCredentialMaximumDeclaration(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Credentials
	profile, receiver, trust := c.Profiles[0], c.Receivers[0], c.TrustPolicies[0]
	c.Profiles, c.Receivers, c.TrustPolicies, c.MutationOrigins = nil, nil, nil, nil
	for i := range 32 {
		p, policy := profile, trust
		p.ID = fmt.Sprintf("profile-%02d", i)
		policy.ID = fmt.Sprintf("trust-%02d", i)
		p.TrustPolicy = policy.ID
		c.Profiles = append(c.Profiles, p)
		c.TrustPolicies = append(c.TrustPolicies, policy)
		c.MutationOrigins = append(c.MutationOrigins, fmt.Sprintf("https://console-%02d.example.test", i))
	}
	for i := range 64 {
		r := receiver
		r.Subject = fmt.Sprintf("svc:owner-%02d", i)
		r.Profiles = []string{c.Profiles[i%32].ID}
		r.TrustPolicy = c.TrustPolicies[i%32].ID
		c.Receivers = append(c.Receivers, r)
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromBytes(body); err != nil {
		t.Fatal("maximum declaration rejected", err)
	}
}

func TestAcceptedGrantRevisionsAndConsentNarrowing(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Credentials.Profiles[0]
	p.Revision = 3
	p.AcceptedGrantRevisions = []uint64{1, 3}
	g := authntokens.GrantConstraints{Version: 1, ProfileID: p.ID, ProfileRevision: 1, Audience: p.Audience, Scopes: []string{"reports:read", "removed:read"}, Namespaces: []string{"workspace", "removed"}, Selection: authntokens.ResourceSelection{Mode: authntokens.Selected, Resources: []authntokens.ResourceRef{{Namespace: "workspace", ID: "north-branch"}, {Namespace: "removed", ID: "north-branch"}}}}
	before, _ := json.Marshal(g)
	out, err := p.Narrow(&g)
	if err != nil || out.ProfileRevision != 1 || len(out.Scopes) != 1 || len(out.Namespaces) != 1 || len(out.Selection.Resources) != 1 {
		t.Fatal("narrowing changed authority", err)
	}
	after, _ := json.Marshal(g)
	if !bytes.Equal(before, after) {
		t.Fatal("stored consent mutated")
	}
	p.Namespaces = append(p.Namespaces, "new")
	p.Scopes = append(p.Scopes, CredentialScope{Scope: "new:read", DecisionProfile: "new"})
	out, err = p.Narrow(&g)
	if err != nil || len(out.Scopes) != 1 || len(out.Namespaces) != 1 {
		t.Fatal("expansion widened old grant", err)
	}
	for _, revisions := range [][]uint64{nil, {}, {1, 1, 3}, {1, 4, 3}, {0, 3}, {1, 2}} {
		p.AcceptedGrantRevisions = revisions
		if _, err := p.Narrow(&g); err == nil {
			t.Fatal("incompatible revision accepted", revisions)
		}
	}
	p.AcceptedGrantRevisions = []uint64{1, 3}
	p.Audience += "/changed"
	if _, err := p.Narrow(&g); err == nil {
		t.Fatal("audience changed")
	}
	for _, literal := range []string{"[]", "[0, 1]", "[1, 1]", "[1, 2]", "[2]"} {
		raw := strings.Replace(credentialDeclaration, "revision: 1", "revision: 1\n      accepted_grant_revisions: "+literal, 1)
		if _, err := LoadFromBytes([]byte(credentialBase + raw)); err == nil {
			t.Fatal("invalid revision declaration", literal)
		}
	}
}

func credentialReceiverFixture() (common, declaration string) {
	transport := `router_base_url: https://router.example.test
sts_endpoint: https://id.example.test/sts/token
audience: https://router.example.test
service_name: issuer
assertion_audience: https://id.example.test/sts/token
router_timeout: 5s
jwt: {private_key_file: /service/key.pem, public_key_file: /service/public.pem}
`
	declaration = strings.Replace(credentialDeclaration, "enabled: false", "enabled: true", 1)
	declaration += "  decisions:\n" + "    " + strings.ReplaceAll(strings.TrimSpace(transport), "\n", "\n    ") + "\n"
	common = credentialBase + "cookie: {secure: true}\naudit_outbox_enabled: true\ntls: {enabled: true, cert_file: /server/cert.pem, key_file: /server/key.pem, client_ca_file: /general/ca.pem}\naudit:\n  " + strings.ReplaceAll(strings.TrimSpace(transport), "\n", "\n  ") + "\n"
	return common, declaration
}
func TestCredentialReceiverPreflightIsSharedWithHelper(t *testing.T) {
	common, declaration := credentialReceiverFixture()
	if _, err := LoadFromBytesWithCredentialReceiver([]byte(common + declaration)); err != nil {
		t.Fatal("compatible receiver preflight rejected", err)
	}
	if _, err := LoadFromBytes([]byte(common + declaration)); err == nil {
		t.Fatal("default reader activated issuer")
	}
	for _, change := range []struct{ old, new string }{{"cookie: {secure: true}", "cookie: {name: __Host-reports-consent, secure: true}"}, {"cookie: {secure: true}", "cookie: {secure: false}"}, {"audit_outbox_enabled: true", "audit_outbox_enabled: false"}, {"tls: {enabled: true, cert_file: /server/cert.pem, key_file: /server/key.pem, client_ca_file: /general/ca.pem}", ""}} {
		if _, err := LoadFromBytesWithCredentialReceiver([]byte(strings.Replace(common, change.old, change.new, 1) + declaration)); err == nil {
			t.Fatal("unsafe receiver declaration accepted", change.old)
		}
	}
}

func TestManualIssuanceProfilePolicy(t *testing.T) {
	for _, policy := range []string{"{family: api_key, max_ttl: 24h}", "{family: connection, max_ttl: 1h}", "{family: connection, max_ttl: 168h}"} {
		declaration := strings.Replace(credentialDeclaration, "      revision:", "      manual_issuance: "+policy+"\n      revision:", 1)
		// Use a seven-day parent so both historical manual connection boundaries fit.
		declaration = strings.Replace(declaration, "grant_ttl: 24h", "grant_ttl: 168h", 1)
		cfg, err := LoadFromBytes([]byte(credentialBase + declaration))
		if err != nil || cfg.Credentials.Profiles[0].ManualIssuance == nil {
			t.Fatal(policy, err)
		}
	}
	for _, policy := range []string{"{family: oauth, max_ttl: 1h}", "{family: connection}", "{family: connection, max_ttl: 30m}", "{family: connection, max_ttl: 169h}", "{family: connection, max_ttl: -1h}", "{family: api_key, max_ttl: 1500ms}", "{family: api_key, max_ttl: 169h}", "{family: api_key, max_ttl: 1h, allow_refresh: true}"} {
		declaration := strings.Replace(credentialDeclaration, "      revision:", "      manual_issuance: "+policy+"\n      revision:", 1)
		declaration = strings.Replace(declaration, "grant_ttl: 24h", "grant_ttl: 168h", 1)
		if _, err := LoadFromBytes([]byte(credentialBase + declaration)); err == nil {
			t.Fatal("unsafe manual policy accepted", policy)
		}
	}
	cfg, err := LoadFromBytes([]byte(credentialBase + credentialDeclaration))
	if err != nil || cfg.Credentials.Profiles[0].ManualIssuance != nil {
		t.Fatal("omission changed legacy policy", err)
	}
}

func TestManualIssuanceRequiresCompatibleReceiver(t *testing.T) {
	common, declaration := credentialReceiverFixture()
	declaration = strings.Replace(declaration, "      revision:", "      manual_issuance: {family: connection, max_ttl: 24h}\n      revision:", 1)
	body := []byte(common + declaration)
	if _, err := LoadFromBytesWithCredentialReceiver(body); err == nil {
		t.Fatal("old receiver ignored manual policy")
	}
	if _, err := LoadFromBytesWithManualIssuance(body); err != nil {
		t.Fatal("compatible receiver rejected", err)
	}
}
