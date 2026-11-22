package authntokens

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/caller"
)

func TestLegacyResponsesOmitIdentity(t *testing.T) {
	for _, response := range []any{ValidateResponse{}, DelegationResult{}} {
		body, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "identity") {
			t.Fatalf("legacy response changed: %s", body)
		}
	}
}

func TestValidatedTokenResponseCarriesCallerBinding(t *testing.T) {
	input := ValidateResponse{Identity: &caller.Identity{Version: caller.Version, CallerKind: caller.Agent,
		CallerID: "caller:1", OwnerSubject: "user:1", EffectiveSubject: "user:1",
		CredentialKind: caller.APIKey, CredentialID: "key:1", Assurance: caller.Verified}}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output ValidateResponse
	if err := json.Unmarshal(body, &output); err != nil || output.Identity == nil {
		t.Fatalf("missing caller binding: %v", err)
	}
	if err := output.Identity.Validate(); err != nil || *output.Identity != *input.Identity {
		t.Fatalf("caller binding changed: %v", err)
	}
}
