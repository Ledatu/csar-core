package caller

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialBindingIsIndependentOfTransport(t *testing.T) {
	for _, credential := range []CredentialKind{Session, APIKey, OAuthAccess, DelegationProof, STS} {
		for _, kind := range []Kind{Human, Agent, Application, Service} {
			id := Identity{Version: Version, CallerKind: kind, CallerID: "principal:42", OwnerSubject: "owner:7",
				EffectiveSubject: "effective:9", CredentialKind: credential, CredentialID: "credential:1", Assurance: Verified}
			if err := id.Validate(); err != nil {
				t.Fatalf("%s/%s: %v", credential, kind, err)
			}
			encoded, err := json.Marshal(id)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Identity
			if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != id {
				t.Fatalf("identity did not survive JSON roundtrip: %v", err)
			}
		}
	}
}

func TestLegacyCredentialsStayUnknown(t *testing.T) {
	for _, credential := range []CredentialKind{Session, APIKey, OAuthAccess, DelegationProof, STS} {
		id := Identity{Version: Version, CallerKind: Unknown, EffectiveSubject: "owner:7", CredentialKind: credential, Assurance: Legacy}
		if err := id.Validate(); err != nil {
			t.Fatal(err)
		}
		id.CallerKind = Agent
		if err := id.Validate(); err == nil {
			t.Fatal("legacy credential acquired an agent classification")
		}
	}
}

func TestRejectMalformedIdentityWithoutEchoingValues(t *testing.T) {
	var missing *Identity
	if err := missing.Validate(); err == nil {
		t.Fatal("missing identity accepted")
	}
	valid := Identity{Version: Version, CallerKind: Agent, CallerID: "agent:1", OwnerSubject: "user:1",
		EffectiveSubject: "user:1", CredentialKind: APIKey, CredentialID: "key:1", Assurance: Verified}
	cases := map[string]func(*Identity){
		"version":       func(id *Identity) { id.Version = 2 },
		"kind":          func(id *Identity) { id.CallerKind = "robot" },
		"credential":    func(id *Identity) { id.CredentialKind = "bearer" },
		"assurance":     func(id *Identity) { id.Assurance = Legacy },
		"missing ID":    func(id *Identity) { id.CallerID = "" },
		"missing owner": func(id *Identity) { id.OwnerSubject = "" },
		"missing sub":   func(id *Identity) { id.EffectiveSubject = "" },
		"newline":       func(id *Identity) { id.ClientID = "untrusted\nvalue" },
		"long ref":      func(id *Identity) { id.ConnectionID = strings.Repeat("x", 257) },
		"whitespace":    func(id *Identity) { id.CredentialID = "Bearer sensitive-token" },
		"unknown ID":    func(id *Identity) { id.CallerKind, id.Assurance = Unknown, Legacy },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			id := valid
			mutate(&id)
			err := id.Validate()
			if err == nil {
				t.Fatal("malformed identity accepted")
			}
			if strings.Contains(err.Error(), "sensitive-token") || strings.Contains(err.Error(), "untrusted") {
				t.Fatal("error echoed an untrusted reference")
			}
		})
	}
}
