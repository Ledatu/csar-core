package authzconfig

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/configutil"
	"gopkg.in/yaml.v3"
)

const ServicePoliciesVersion = 1

// ServicePolicyConfig is a declaration, not a second permission engine. Runtime
// enablement stays rejected until the service implements the capability checks.
type ServicePolicyConfig struct {
	Version          int                      `yaml:"version"`
	Enabled          bool                     `yaml:"enabled"`
	DecisionProfiles []ServiceDecisionProfile `yaml:"decision_profiles"`
	Services         []ServiceCapability      `yaml:"services"`
}

// ServiceDecisionProfile fixes the requested permission and resource audience.
// Authz's existing engine remains responsible for live permission matching.
type ServiceDecisionProfile struct {
	ID       string                `yaml:"id"`
	Audience string                `yaml:"audience"`
	Resource string                `yaml:"resource"`
	Action   string                `yaml:"action"`
	Bindings []ServiceScopeBinding `yaml:"bindings"`
}

// Tenant bindings append the exact resource ID to a bounded literal prefix.
// An explicit platform alternative has an empty prefix and cannot imply a tenant.
type ServiceScopeBinding struct {
	Namespace     string `yaml:"namespace"`
	ScopeType     string `yaml:"scope_type"`
	ScopeIDPrefix string `yaml:"scope_id_prefix"`
}

type ServiceCapability struct {
	Subject    string             `yaml:"subject"`
	Operations []ServiceOperation `yaml:"operations"`
}

// Subject modes constrain on-behalf-of decisions/listing. Assignment reads and
// tenant role mutations are separate capabilities, never inherited from decide.
// Roles are permitted only on grant_role/revoke_role and retain the global ceiling.
type ServiceOperation struct {
	Operation    string   `yaml:"operation"`
	Profiles     []string `yaml:"profiles"`
	SubjectModes []string `yaml:"subject_modes,omitempty"`
	Roles        []string `yaml:"roles,omitempty"`
}

func (c *ServicePolicyConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain ServicePolicyConfig
	var decoded plain
	if err := configutil.DecodeStrictYAML(node, &decoded); err != nil {
		return err
	}
	*c = ServicePolicyConfig(decoded)
	return nil
}

func (c *ServicePolicyConfig) validate(roles map[string]struct{}, ceiling []string) error {
	return c.validateRuntime(roles, ceiling, false)
}

func (c *ServicePolicyConfig) validateRuntime(roles map[string]struct{}, ceiling []string, decisionsSupported bool) error {
	if c == nil {
		return nil
	}
	if c.Version != ServicePoliciesVersion {
		return fmt.Errorf("service_policies: unsupported version")
	}
	if c.Enabled && !decisionsSupported {
		return fmt.Errorf("service_policies: runtime activation is not supported")
	}
	if len(c.DecisionProfiles) < 1 || len(c.DecisionProfiles) > 32 || len(c.Services) > 64 {
		return fmt.Errorf("service_policies: invalid policy collection size")
	}
	profiles := make(map[string]*ServiceDecisionProfile, len(c.DecisionProfiles))
	for i := range c.DecisionProfiles {
		profile := &c.DecisionProfiles[i]
		if profiles[profile.ID] != nil {
			return fmt.Errorf("service_policies: duplicate decision profile")
		}
		if err := profile.validate(); err != nil {
			return err
		}
		profiles[profile.ID] = profile
	}
	subjects := make(map[string]bool, len(c.Services))
	for _, service := range c.Services {
		if !strings.HasPrefix(service.Subject, "svc:") || service.Subject == "svc:" || !caller.ValidReference(service.Subject) || subjects[service.Subject] || len(service.Operations) < 1 || len(service.Operations) > 6 {
			return fmt.Errorf("service_policies: invalid or duplicate service capability")
		}
		operations := make(map[string]bool, len(service.Operations))
		for i := range service.Operations {
			op := &service.Operations[i]
			if c.Enabled && op.Operation != "decide" {
				return fmt.Errorf("service_policies: receiver does not support configured operation")
			}
			if operations[op.Operation] {
				return fmt.Errorf("service_policies: duplicate service operation")
			}
			if err := op.validate(profiles, roles, ceiling); err != nil {
				return err
			}
			operations[op.Operation] = true
		}
		subjects[service.Subject] = true
	}
	return nil
}

func (p *ServiceDecisionProfile) validate() error {
	if !authntokens.ValidProfileID(p.ID) || !authntokens.ValidAudience(p.Audience) || p.Resource == "" || !caller.ValidReference(p.Resource) || p.Action == "" || !caller.ValidReference(p.Action) || len(p.Bindings) < 1 || len(p.Bindings) > 2*authntokens.MaxNamespaces {
		return fmt.Errorf("service_policies: invalid decision profile")
	}
	bindings := make(map[[2]string]bool, len(p.Bindings))
	namespaces := make(map[string]bool, len(p.Bindings))
	prefixes := make(map[string]bool, len(p.Bindings))
	for _, binding := range p.Bindings {
		key := [2]string{binding.Namespace, binding.ScopeType}
		if !authntokens.ValidNamespace(binding.Namespace) || bindings[key] {
			return fmt.Errorf("service_policies: invalid or duplicate namespace binding")
		}
		switch binding.ScopeType {
		case "tenant":
			// Delimiting the prefix and excluding colons from resource IDs
			// makes different prefixes injective without marketplace parsing.
			if !strings.HasSuffix(binding.ScopeIDPrefix, ":") || len(binding.ScopeIDPrefix) > 256-authntokens.MaxResourceIDBytes || !caller.ValidReference(binding.ScopeIDPrefix) || prefixes[binding.ScopeIDPrefix] {
				return fmt.Errorf("service_policies: invalid or aliased tenant scope prefix")
			}
			prefixes[binding.ScopeIDPrefix] = true
		case "platform":
			if binding.ScopeIDPrefix != "" {
				return fmt.Errorf("service_policies: platform scope must have an empty ID")
			}
		default:
			return fmt.Errorf("service_policies: unsupported scope type")
		}
		bindings[key] = true
		namespaces[binding.Namespace] = true
	}
	if len(namespaces) > authntokens.MaxNamespaces {
		return fmt.Errorf("service_policies: too many namespaces")
	}
	return nil
}

func (op *ServiceOperation) validate(profiles map[string]*ServiceDecisionProfile, roles map[string]struct{}, ceiling []string) error {
	if len(op.Profiles) < 1 || len(op.Profiles) > len(profiles) {
		return fmt.Errorf("service_policies: invalid operation profile count")
	}
	for i, id := range op.Profiles {
		if profiles[id] == nil || slices.Contains(op.Profiles[:i], id) {
			return fmt.Errorf("service_policies: unknown or duplicate operation profile")
		}
	}
	switch op.Operation {
	case "decide", "list_subject_scopes":
		if len(op.Roles) != 0 || len(op.SubjectModes) < 1 || len(op.SubjectModes) > 2 {
			return fmt.Errorf("service_policies: invalid subject decision capability")
		}
		for i, mode := range op.SubjectModes {
			if mode != "request_bound" && mode != "background" || slices.Contains(op.SubjectModes[:i], mode) {
				return fmt.Errorf("service_policies: invalid subject mode")
			}
		}
	case "list_scope_assignments", "query_assignments":
		if len(op.Roles) != 0 || len(op.SubjectModes) != 0 {
			return fmt.Errorf("service_policies: assignment listing cannot grant subject or role capabilities")
		}
	case "grant_role", "revoke_role":
		if len(op.SubjectModes) != 0 || len(op.Roles) < 1 || len(op.Roles) > 32 {
			return fmt.Errorf("service_policies: invalid tenant role capability")
		}
		for i, role := range op.Roles {
			_, exists := roles[role]
			if !exists || !slices.Contains(ceiling, role) || slices.Contains(op.Roles[:i], role) {
				return fmt.Errorf("service_policies: role outside configured service ceiling")
			}
		}
		for _, id := range op.Profiles {
			for _, binding := range profiles[id].Bindings {
				if binding.ScopeType != "tenant" {
					return fmt.Errorf("service_policies: role writes require tenant-only profiles")
				}
			}
		}
	default:
		return fmt.Errorf("service_policies: unsupported service operation")
	}
	return nil
}
