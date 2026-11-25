package authntokens

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func validConstraints() GrantConstraints {
	return GrantConstraints{Version: ConstraintsVersion, ProfileID: "reports", ProfileRevision: 1,
		Audience: "https://reports.example.test", Scopes: []string{"reports:read"}, Namespaces: []string{"workspace"},
		Selection: ResourceSelection{Mode: Selected, Resources: []ResourceRef{{Namespace: "workspace", ID: "north-branch"}}}}
}

func TestGrantConstraintsIsolation(t *testing.T) {
	var absent *GrantConstraints
	if absent.Validate() == nil {
		t.Fatal("absent consent accepted")
	}
	for name, mutate := range map[string]func(*GrantConstraints){
		"unchanged":       func(*GrantConstraints) {},
		"explicit future": func(g *GrantConstraints) { g.Selection = ResourceSelection{Mode: CurrentAndFuture} },
		"equal IDs in different namespaces": func(g *GrantConstraints) {
			g.Namespaces = append(g.Namespaces, "project")
			g.Selection.Resources = append(g.Selection.Resources, ResourceRef{Namespace: "project", ID: "north-branch"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := validConstraints()
			mutate(&g)
			if err := g.Validate(); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			var decoded GrantConstraints
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatal(err)
			}
			if err := decoded.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, mutate := range map[string]func(*GrantConstraints){
		"zero version":        func(g *GrantConstraints) { g.Version = 0 },
		"future version":      func(g *GrantConstraints) { g.Version++ },
		"zero revision":       func(g *GrantConstraints) { g.ProfileRevision = 0 },
		"missing profile":     func(g *GrantConstraints) { g.ProfileID = "" },
		"empty namespaces":    func(g *GrantConstraints) { g.Namespaces = nil },
		"duplicate namespace": func(g *GrantConstraints) { g.Namespaces = append(g.Namespaces, g.Namespaces[0]) },
		"empty scopes":        func(g *GrantConstraints) { g.Scopes = nil },
		"duplicate scope":     func(g *GrantConstraints) { g.Scopes = append(g.Scopes, g.Scopes[0]) },
		"unknown selection":   func(g *GrantConstraints) { g.Selection.Mode = "all" },
		"empty selected":      func(g *GrantConstraints) { g.Selection.Resources = nil },
		"future with refs":    func(g *GrantConstraints) { g.Selection.Mode = CurrentAndFuture },
		"wrong namespace":     func(g *GrantConstraints) { g.Selection.Resources[0].Namespace = "project" },
		"duplicate ref": func(g *GrantConstraints) {
			g.Selection.Resources = append(g.Selection.Resources, g.Selection.Resources[0])
		},
		"bad audience": func(g *GrantConstraints) { g.Audience += "?token=secret" },
	} {
		t.Run(name, func(t *testing.T) {
			g := validConstraints()
			mutate(&g)
			if g.Validate() == nil {
				t.Fatal("invalid consent accepted")
			}
		})
	}
}

func TestResourceAndScopeBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		valid  func(string) bool
		max    int
		prefix string
	}{
		{"namespace", ValidNamespace, MaxNamespaceBytes, "n"},
		{"resource", ValidResourceID, MaxResourceIDBytes, "R"},
		{"profile", ValidProfileID, MaxProfileIDBytes, "P"},
		{"scope", ValidScope, MaxScopeBytes, "s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.valid(strings.Repeat(tc.prefix, tc.max)) || tc.valid(strings.Repeat(tc.prefix, tc.max+1)) || tc.valid("") {
				t.Fatal("incorrect length bound")
			}
			for _, bad := range []string{" bad", "bad ", "bad\n", "bad,other", "кириллица", "bad\\id", "bad\"id"} {
				if tc.valid(bad) {
					t.Fatalf("unsafe %s accepted", tc.name)
				}
			}
		})
	}
	for _, id := range []string{"north-branch", "A_12.v2", "b4f608f2-2c6a-4541-ab21-ad70c26f3e56"} {
		if (ResourceRef{Namespace: "workspace", ID: id}).Validate() != nil {
			t.Fatal("literal ID rejected")
		}
	}
	for _, id := range []string{"../branch", "branch/path", "branch%2Fpath", "*", ".hidden"} {
		if ValidResourceID(id) {
			t.Fatal("nonliteral resource ID accepted")
		}
	}
	for _, scope := range []ScopeRef{{Type: "tenant", ID: "workspace:north-branch"}, {Type: "platform"}, {Type: "tenant", ID: strings.Repeat("x", 256)}} {
		if scope.Validate() != nil {
			t.Fatal("valid scope rejected")
		}
	}
	for _, scope := range []ScopeRef{{Type: "tenant"}, {Type: "platform", ID: "workspace:north-branch"}, {Type: "workspace", ID: "north-branch"}, {Type: "tenant", ID: "*"}, {Type: "tenant", ID: strings.Repeat("x", 257)}} {
		if scope.Validate() == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}

func TestAudienceIsExactHTTPS(t *testing.T) {
	for _, audience := range []string{"https://reports.example.test", "https://reports.example.test/", "https://reports.example.test:8443/v1"} {
		if !ValidAudience(audience) {
			t.Fatal("HTTPS audience rejected")
		}
	}
	for _, audience := range []string{"http://reports.example.test", "https:///path", "https://user@reports.example.test", "https://reports.example.test#", "https://reports.example.test?", "https://*.example.test", "https://reports.example.test:", "https://reports.example.test:invalid", "https://reports.example.test/a\nb", "https://reports.example.test/" + strings.Repeat("x", MaxAudienceBytes)} {
		if ValidAudience(audience) {
			t.Fatal("unsafe audience accepted")
		}
	}
}

func TestMaximumConsentEnvelope(t *testing.T) {
	g := validConstraints()
	g.ProfileID = strings.Repeat("p", MaxProfileIDBytes)
	g.Audience = "https://reports.example.test/" + strings.Repeat("a", MaxAudienceBytes-len("https://reports.example.test/"))
	g.ProfileRevision = ^uint64(0)
	g.Namespaces = nil
	for i := range MaxNamespaces {
		g.Namespaces = append(g.Namespaces, fmt.Sprintf("n%02d", i)+strings.Repeat("n", MaxNamespaceBytes-3))
	}
	g.Scopes = nil
	// HTML-sensitive scope bytes exercise encoding/json's widest escaped form.
	for i := range MaxScopes {
		g.Scopes = append(g.Scopes, fmt.Sprintf("%03d", i)+strings.Repeat("<", MaxScopeBytes-3))
	}
	g.Selection.Resources = nil
	for i := range MaxSelectedResources {
		g.Selection.Resources = append(g.Selection.Resources, ResourceRef{Namespace: g.Namespaces[i%MaxNamespaces], ID: fmt.Sprintf("%03d", i) + strings.Repeat("i", MaxResourceIDBytes-3)})
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= MaxConsentResponseBytes {
		t.Fatalf("consent exceeds response envelope: %d", len(body))
	}
	refs, err := json.Marshal(g.Selection.Resources[:MaxDecisionResources])
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) >= MaxCandidateRequestBytes {
		t.Fatal("candidate list exceeds request envelope")
	}
	if err := ValidateResources(g.Selection.Resources[:MaxDecisionResources], MaxDecisionResources); err != nil {
		t.Fatal(err)
	}
	if ValidateResources(g.Selection.Resources[:MaxDecisionResources+1], MaxDecisionResources) == nil {
		t.Fatal("oversized decision batch accepted")
	}
	g.Selection.Resources = append(g.Selection.Resources, ResourceRef{Namespace: g.Namespaces[0], ID: "extra"})
	if g.Validate() == nil {
		t.Fatal("oversized selection accepted")
	}
	g = validConstraints()
	for len(g.Namespaces) <= MaxNamespaces {
		g.Namespaces = append(g.Namespaces, fmt.Sprintf("n%d", len(g.Namespaces)))
	}
	if g.Validate() == nil {
		t.Fatal("oversized namespace set accepted")
	}
	g = validConstraints()
	for len(g.Scopes) <= MaxScopes {
		g.Scopes = append(g.Scopes, fmt.Sprintf("scope%d", len(g.Scopes)))
	}
	if g.Validate() == nil {
		t.Fatal("oversized scope set accepted")
	}
}
