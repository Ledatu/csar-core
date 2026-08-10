package s3store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ledatu/csar-core/tokenmint"
)

func validDescriptor() tokenmint.Descriptor {
	return tokenmint.Descriptor{
		Kind:            tokenmint.KindOAuth2ClientCredentials,
		GrantProfile:    "ozon-performance",
		ClientIDRef:     "accounts/ozon/123/performance/client_id",
		ClientSecretRef: "accounts/ozon/123/performance/client_secret",
	}
}

func TestEncodeDescriptor_Roundtrip(t *testing.T) {
	obj, err := EncodeDescriptor(validDescriptor())
	if err != nil {
		t.Fatalf("EncodeDescriptor: %v", err)
	}

	body, err := MarshalTokenObject(&obj)
	if err != nil {
		t.Fatalf("MarshalTokenObject: %v", err)
	}

	// A descriptor must never serialize a value field.
	if strings.Contains(string(body), "plaintext") || strings.Contains(string(body), "enc_token") {
		t.Errorf("descriptor JSON carries a value field: %s", body)
	}

	parsed, err := ParseTokenObject(body)
	if err != nil {
		t.Fatalf("ParseTokenObject: %v", err)
	}
	if !parsed.IsDescriptor() {
		t.Fatal("parsed object is not a descriptor")
	}
	if got := parsed.Descriptor(); got != validDescriptor() {
		t.Errorf("Descriptor = %+v, want %+v", got, validDescriptor())
	}
}

func TestEncodeDescriptor_RejectsInvalid(t *testing.T) {
	d := validDescriptor()
	d.ClientSecretRef = ""
	if _, err := EncodeDescriptor(d); err == nil {
		t.Fatal("EncodeDescriptor accepted a descriptor with no client_secret_ref")
	}
}

func TestParseTokenObject_RejectsMixedObject(t *testing.T) {
	// A descriptor that also carries a stored value is what tampering looks
	// like, not a format we resolve by precedence.
	for _, body := range []string{
		`{"kind":"oauth2_client_credentials","grant_profile":"p","client_id_ref":"a","client_secret_ref":"b","plaintext":"leak"}`,
		`{"kind":"oauth2_client_credentials","grant_profile":"p","client_id_ref":"a","client_secret_ref":"b","enc_token":"AAAA","kms_key_id":"k"}`,
	} {
		_, err := ParseTokenObject([]byte(body))
		if err == nil {
			t.Fatalf("ParseTokenObject accepted a mixed object: %s", body)
		}
		if !strings.Contains(err.Error(), "descriptor") {
			t.Errorf("error %q should name the descriptor conflict", err)
		}
	}
}

func TestParseTokenObject_RejectsUnknownKind(t *testing.T) {
	body := `{"kind":"saml_assertion","grant_profile":"p","client_id_ref":"a","client_secret_ref":"b"}`
	if _, err := ParseTokenObject([]byte(body)); err == nil {
		t.Fatal("ParseTokenObject accepted an unknown descriptor kind")
	}
}

func TestParseTokenObject_RejectsIncompleteDescriptor(t *testing.T) {
	body := `{"kind":"oauth2_client_credentials","grant_profile":"p"}`
	if _, err := ParseTokenObject([]byte(body)); err == nil {
		t.Fatal("ParseTokenObject accepted a descriptor with no credential refs")
	}
}

func TestParseTokenObject_LegacyFormatsStillParse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"passthrough", `{"plaintext":"Bearer sk-test"}`},
		{"kms", `{"enc_token":"YWJj","kms_key_id":"abj-1"}`},
		{"passthrough with metadata", `{"plaintext":"x","updated_by":"svc:campaigns","schema_version":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := ParseTokenObject([]byte(tc.body))
			if err != nil {
				t.Fatalf("ParseTokenObject: %v", err)
			}
			if obj.IsDescriptor() {
				t.Error("legacy object was classified as a descriptor")
			}
		})
	}
}

func TestDecodeToken_DescriptorIgnoresKMSMode(t *testing.T) {
	obj, err := EncodeDescriptor(validDescriptor())
	if err != nil {
		t.Fatalf("EncodeDescriptor: %v", err)
	}

	// A descriptor holds no ciphertext, so both modes must surface it
	// identically rather than failing the "requires plaintext/enc_token" check.
	for _, mode := range []string{"passthrough", "kms"} {
		decoded, err := DecodeToken(&obj, mode)
		if err != nil {
			t.Fatalf("DecodeToken(%s): %v", mode, err)
		}
		if decoded.Descriptor == nil {
			t.Fatalf("DecodeToken(%s) returned no descriptor", mode)
		}
		if decoded.Plaintext != "" || len(decoded.EncryptedToken) != 0 {
			t.Errorf("DecodeToken(%s) returned token material for a descriptor", mode)
		}
	}
}

func TestTokenObject_DescriptorFieldsOmittedForStaticTokens(t *testing.T) {
	obj, err := EncodeToken([]byte("secret"), "", "passthrough")
	if err != nil {
		t.Fatalf("EncodeToken: %v", err)
	}
	body, err := MarshalTokenObject(&obj)
	if err != nil {
		t.Fatalf("MarshalTokenObject: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"kind", "grant_profile", "client_id_ref", "client_secret_ref"} {
		if _, present := raw[key]; present {
			t.Errorf("static token object should not emit %q", key)
		}
	}
}
