package authzconfig

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const servicePolicyBase = `policy:
  roles:
    - name: report_reader
      permissions: [{resource: report, action: read}]
    - name: privileged_operator
admin:
  service_assignable_roles: [report_reader]
`

const servicePolicyDeclaration = `service_policies:
  version: 1
  enabled: false
  decision_profiles:
    - id: report-reader
      audience: https://reports.example.test
      resource: report
      action: read
      bindings:
        - namespace: workspace
          scope_type: tenant
          scope_id_prefix: 'workspace:'
  services:
    - subject: svc:resource-owner
      operations:
        - operation: decide
          profiles: [report-reader]
          subject_modes: [request_bound]
        - operation: list_subject_scopes
          profiles: [report-reader]
          subject_modes: [request_bound]
        - operation: list_scope_assignments
          profiles: [report-reader]
        - operation: query_assignments
          profiles: [report-reader]
        - operation: grant_role
          profiles: [report-reader]
          roles: [report_reader]
        - operation: revoke_role
          profiles: [report-reader]
          roles: [report_reader]
    - subject: svc:workflow
      operations:
        - operation: decide
          profiles: [report-reader]
          subject_modes: [background]
`

func TestServicePoliciesDeclareIsolatedCapabilities(t *testing.T) {
	for name, declaration := range map[string]string{
		"unrelated application": servicePolicyDeclaration,
		"Aurum deployment data": strings.NewReplacer("reports.example.test", "mcp.aurum-sky.net", "workspace", "wildberries", "resource: report", "resource: campaign_module", "action: read", "action: analytics.read", "svc:resource-owner", "svc:aurumskynet-campaigns", "svc:workflow", "svc:aurumskynet-buyers").Replace(servicePolicyDeclaration),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(servicePolicyBase + declaration))
			if err != nil {
				t.Fatal(err)
			}
			c := cfg.ServicePolicies
			if c.Enabled || len(c.Services) != 2 || len(c.Services[1].Operations) != 1 || c.Services[1].Operations[0].Operation != "decide" || !slices.Equal(c.Services[1].Operations[0].SubjectModes, []string{"background"}) {
				t.Fatal("service capabilities were activated, merged or widened")
			}
			if len(cfg.Admin.ServiceAssignableRoles) != 1 || cfg.Admin.ServiceAssignableRoles[0] != "report_reader" {
				t.Fatal("global service role ceiling changed")
			}
		})
	}
	for _, data := range []string{"", servicePolicyBase} {
		cfg, err := LoadFromBytes([]byte(data))
		if err != nil || cfg.ServicePolicies != nil {
			t.Fatal("absent declaration changed legacy behavior", err)
		}
	}
	_, err := LoadFromBytes([]byte(servicePolicyBase + strings.Replace(servicePolicyDeclaration, "enabled: false", "enabled: true", 1)))
	if err == nil || !strings.Contains(err.Error(), "runtime activation is not supported") {
		t.Fatal("unsupported activation accepted", err)
	}
}

func TestServicePoliciesRejectUnsafeDeclarations(t *testing.T) {
	for name, change := range map[string]func(string) string{
		"unknown version": func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) },
		"missing version": func(s string) string { return strings.Replace(s, "  version: 1\n", "", 1) },
		"unknown field":   func(s string) string { return s + "  allow_any_subject: true\n" },
		"nested unknown field": func(s string) string {
			return strings.Replace(s, "action: read", "action: read\n      allow_any_resource: true", 1)
		},
		"null policy":       func(string) string { return "service_policies: null\n" },
		"empty policy":      func(string) string { return "service_policies: {}\n" },
		"null service":      func(s string) string { return strings.Replace(s, "  services:\n", "  services:\n    - null\n", 1) },
		"duplicate field":   func(s string) string { return strings.Replace(s, "version: 1", "version: 1\n  version: 1", 1) },
		"trailing document": func(s string) string { return s + "---\nservice_policies: {}\n" },
		"wildcard service":  func(s string) string { return strings.Replace(s, "svc:workflow", "svc:*", 1) },
		"prefix only":       func(s string) string { return strings.Replace(s, "svc:workflow", "'svc:'", 1) },
		"nonservice":        func(s string) string { return strings.Replace(s, "svc:workflow", "owner", 1) },
		"unknown profile": func(s string) string {
			return strings.Replace(s, "profiles: [report-reader]", "profiles: [unknown]", 1)
		},
		"duplicate profile reference": func(s string) string {
			return strings.Replace(s, "profiles: [report-reader]", "profiles: [report-reader, report-reader]", 1)
		},
		"unknown capability": func(s string) string { return strings.Replace(s, "operation: decide", "operation: impersonate", 1) },
		"unknown mode": func(s string) string {
			return strings.Replace(s, "subject_modes: [request_bound]", "subject_modes: [any_subject]", 1)
		},
		"empty mode": func(s string) string {
			return strings.Replace(s, "subject_modes: [request_bound]", "subject_modes: []", 1)
		},
		"duplicate mode": func(s string) string {
			return strings.Replace(s, "subject_modes: [request_bound]", "subject_modes: [request_bound, request_bound]", 1)
		},
		"decision grants roles": func(s string) string {
			return strings.Replace(s, "subject_modes: [request_bound]", "subject_modes: [request_bound]\n          roles: [report_reader]", 1)
		},
		"assignment listing grants subject": func(s string) string {
			return strings.Replace(s, "operation: query_assignments", "operation: query_assignments\n          subject_modes: [background]", 1)
		},
		"assignment listing grants role": func(s string) string {
			return strings.Replace(s, "operation: query_assignments", "operation: query_assignments\n          roles: [report_reader]", 1)
		},
		"role grant uses subject mode": func(s string) string {
			return strings.Replace(s, "operation: grant_role", "operation: grant_role\n          subject_modes: [background]", 1)
		},
		"unknown role": func(s string) string { return strings.Replace(s, "roles: [report_reader]", "roles: [unknown]", 1) },
		"role above ceiling": func(s string) string {
			return strings.Replace(s, "roles: [report_reader]", "roles: [privileged_operator]", 1)
		},
		"empty role set": func(s string) string { return strings.Replace(s, "roles: [report_reader]", "roles: []", 1) },
		"duplicate role": func(s string) string {
			return strings.Replace(s, "roles: [report_reader]", "roles: [report_reader, report_reader]", 1)
		},
		"nonliteral resource":     func(s string) string { return strings.Replace(s, "resource: report", "resource: '*'", 1) },
		"nonliteral action":       func(s string) string { return strings.Replace(s, "action: read", "action: '{body.action}'", 1) },
		"foreign scope type":      func(s string) string { return strings.Replace(s, "scope_type: tenant", "scope_type: workspace", 1) },
		"wildcard namespace":      func(s string) string { return strings.Replace(s, "namespace: workspace", "namespace: '*'", 1) },
		"wildcard scope":          func(s string) string { return strings.Replace(s, "'workspace:'", "'*:'", 1) },
		"scope template":          func(s string) string { return strings.Replace(s, "'workspace:'", "'{path.resource}:'", 1) },
		"undelimited scope":       func(s string) string { return strings.Replace(s, "'workspace:'", "'workspace'", 1) },
		"oversized prefix":        func(s string) string { return strings.Replace(s, "'workspace:'", "'"+strings.Repeat("w", 64)+":'", 1) },
		"nonempty platform scope": func(s string) string { return strings.Replace(s, "scope_type: tenant", "scope_type: platform", 1) },
		"platform mutation": func(s string) string {
			return strings.Replace(strings.Replace(s, "scope_type: tenant", "scope_type: platform", 1), "'workspace:'", "''", 1)
		},
		"wrong audience": func(s string) string {
			return strings.Replace(s, "https://reports.example.test", "https://user:secret-do-not-echo@reports.example.test", 1)
		},
		"aliased bindings": func(s string) string { return strings.Replace(s, "bindings:", "bindings: &shared", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFromBytes([]byte(servicePolicyBase + change(servicePolicyDeclaration)))
			if err == nil {
				t.Fatal("unsafe service policy accepted")
			}
			if strings.Contains(err.Error(), "secret-do-not-echo") {
				t.Fatal("configured value leaked")
			}
		})
	}
}

func TestServicePolicyBindingAndCollectionBounds(t *testing.T) {
	for name, mutate := range map[string]func(*ServicePolicyConfig){
		"duplicate profile": func(c *ServicePolicyConfig) { c.DecisionProfiles = append(c.DecisionProfiles, c.DecisionProfiles[0]) },
		"duplicate service": func(c *ServicePolicyConfig) { c.Services = append(c.Services, c.Services[0]) },
		"duplicate operation": func(c *ServicePolicyConfig) {
			c.Services[1].Operations = append(c.Services[1].Operations, c.Services[1].Operations[0])
		},
		"duplicate binding": func(c *ServicePolicyConfig) {
			p := &c.DecisionProfiles[0]
			p.Bindings = append(p.Bindings, p.Bindings[0])
		},
		"aliased namespace": func(c *ServicePolicyConfig) {
			p := &c.DecisionProfiles[0]
			b := p.Bindings[0]
			b.Namespace = "project"
			p.Bindings = append(p.Bindings, b)
		},
		"too many namespaces": func(c *ServicePolicyConfig) {
			p := &c.DecisionProfiles[0]
			p.Bindings = nil
			for i := range 17 {
				p.Bindings = append(p.Bindings, ServiceScopeBinding{Namespace: fmt.Sprintf("n%d", i), ScopeType: "tenant", ScopeIDPrefix: fmt.Sprintf("scope%d:", i)})
			}
		},
		"too many bindings": func(c *ServicePolicyConfig) {
			c.DecisionProfiles[0].Bindings = slices.Repeat(c.DecisionProfiles[0].Bindings, 33)
		},
		"too many profiles": func(c *ServicePolicyConfig) { c.DecisionProfiles = slices.Repeat(c.DecisionProfiles, 33) },
		"too many services": func(c *ServicePolicyConfig) { c.Services = slices.Repeat(c.Services[:1], 65) },
		"missing profiles":  func(c *ServicePolicyConfig) { c.DecisionProfiles = nil },
		"empty bindings":    func(c *ServicePolicyConfig) { c.DecisionProfiles[0].Bindings = nil },
		"empty operation":   func(c *ServicePolicyConfig) { c.Services[0].Operations[0].Operation = "" },
		"empty profile set": func(c *ServicePolicyConfig) { c.Services[0].Operations[0].Profiles = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte(servicePolicyBase + servicePolicyDeclaration))
			if err != nil {
				t.Fatal(err)
			}
			mutate(cfg.ServicePolicies)
			if cfg.ServicePolicies.validate(map[string]struct{}{"report_reader": {}}, cfg.Admin.ServiceAssignableRoles) == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}

func TestExplicitPlatformAlternativeAndEnvironment(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(servicePolicyBase + servicePolicyDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.ServicePolicies
	// Read-only decisions may declare a separate empty platform scope. This does
	// not permit role mutations or fabricate tenant membership from attribution.
	c.Services = c.Services[1:]
	c.DecisionProfiles[0].Bindings = append(c.DecisionProfiles[0].Bindings, ServiceScopeBinding{Namespace: "workspace", ScopeType: "platform"})
	c.Services[0].Operations[0].SubjectModes = []string{"request_bound", "background"}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromBytes(body); err != nil {
		t.Fatal("explicit platform decision rejected", err)
	}
	t.Setenv("CSAR_TEST_POLICY_ENABLED", "false")
	declaration := strings.Replace(servicePolicyDeclaration, "enabled: false", "enabled: '${CSAR_TEST_POLICY_ENABLED}'", 1)
	if _, err := LoadFromBytes([]byte(servicePolicyBase + declaration)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CSAR_TEST_POLICY_ENABLED", "true")
	if _, err := LoadFromBytes([]byte(servicePolicyBase + declaration)); err == nil || !strings.Contains(err.Error(), "runtime activation") {
		t.Fatal("environment activated unsupported policy", err)
	}
}

func TestServicePolicyMaximumDeclaration(t *testing.T) {
	cfg, err := LoadFromBytes([]byte(servicePolicyBase + servicePolicyDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.ServicePolicies
	profile := c.DecisionProfiles[0]
	c.DecisionProfiles, c.Services = nil, nil
	for i := range 32 {
		p := profile
		p.ID = fmt.Sprintf("profile-%02d", i)
		p.Bindings = nil
		for j := range 16 {
			p.Bindings = append(p.Bindings, ServiceScopeBinding{Namespace: fmt.Sprintf("namespace-%02d", j), ScopeType: "tenant", ScopeIDPrefix: fmt.Sprintf("scope-%02d:", j)})
		}
		c.DecisionProfiles = append(c.DecisionProfiles, p)
	}
	for i := range 64 {
		c.Services = append(c.Services, ServiceCapability{Subject: fmt.Sprintf("svc:owner-%02d", i), Operations: []ServiceOperation{{Operation: "decide", Profiles: []string{c.DecisionProfiles[i%32].ID}, SubjectModes: []string{"request_bound"}}}})
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromBytes(body); err != nil {
		t.Fatal("maximum declaration rejected", err)
	}
}

func TestExplicitDecisionReceiverCapability(t *testing.T) {
	declaration := strings.Replace(servicePolicyDeclaration, "enabled: false", "enabled: true", 1)
	// The initial runtime only implements decisions, not listing or role writes.
	if _, err := LoadFromBytesWithServiceDecisions([]byte(servicePolicyBase + declaration)); err == nil {
		t.Fatal("unsupported operations were accepted by a decision-only receiver")
	}
	cfg, err := LoadFromBytes([]byte(servicePolicyBase + servicePolicyDeclaration))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServicePolicies.Services = cfg.ServicePolicies.Services[1:]
	cfg.ServicePolicies.Enabled = true
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromBytesWithServiceDecisions(body); err != nil {
		t.Fatal("explicit receiver rejected supported decisions", err)
	}
	if _, err := LoadFromBytes(body); err == nil {
		t.Fatal("default/helper loader silently accepted runtime semantics")
	}
}

func TestExplicitFullServiceReceiver(t *testing.T) {
	base := strings.Replace(servicePolicyBase, "admin:\n", "admin:\n  enabled: true\n  allowed_client_cn: gateway\n  tls: {cert_file: server.pem, key_file: server-key.pem, client_ca_file: router-ca.pem}\n", 1)
	declaration := strings.Replace(servicePolicyDeclaration, "enabled: false", "enabled: true", 1)
	body := []byte(base + declaration)
	cfg, err := LoadFromBytesWithServiceCapabilities(body)
	if err != nil || len(cfg.ServicePolicies.Services[0].Operations) != 6 {
		t.Fatal("full receiver rejected isolated operations", err)
	}
	for _, old := range []func([]byte) (*Config, error){LoadFromBytes, LoadFromBytesWithServiceDecisions} {
		if _, err := old(body); err == nil {
			t.Fatal("older receiver accepted unsupported operations")
		}
	}
	for _, change := range []struct{ old, new string }{
		{"enabled: true", "enabled: false"},
		{"allowed_client_cn: gateway", "allowed_client_cn: ''"},
		{"client_ca_file: router-ca.pem", "client_ca_file: ''"},
		{"cert_file: server.pem", "cert_file: ''"},
		{"roles: [report_reader]", "roles: [privileged_operator]"},
	} {
		if _, err := LoadFromBytesWithServiceCapabilities([]byte(strings.Replace(base+declaration, change.old, change.new, 1))); err == nil {
			t.Fatal("unsafe service receiver accepted", change.old)
		}
	}
}
