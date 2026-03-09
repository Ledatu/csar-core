package s3store

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDecodeToken_Passthrough(t *testing.T) {
	obj := TokenObject{Plaintext: "Bearer sk-test-token"}
	decoded, err := DecodeToken(&obj, "passthrough")
	if err != nil {
		t.Fatalf("DecodeToken passthrough: %v", err)
	}
	if decoded.Plaintext != "Bearer sk-test-token" {
		t.Errorf("Plaintext = %q, want %q", decoded.Plaintext, "Bearer sk-test-token")
	}
	if !decoded.Passthrough {
		t.Error("Passthrough should be true")
	}
	if len(decoded.EncryptedToken) != 0 {
		t.Error("EncryptedToken should be empty in passthrough mode")
	}
}

func TestDecodeToken_PassthroughMissingPlaintext(t *testing.T) {
	obj := TokenObject{EncryptedToken: "abc"}
	_, err := DecodeToken(&obj, "passthrough")
	if err == nil {
		t.Fatal("DecodeToken should fail when plaintext is missing in passthrough mode")
	}
}

func TestDecodeToken_KMS(t *testing.T) {
	ciphertext := []byte("encrypted-data-here")
	b64 := base64.StdEncoding.EncodeToString(ciphertext)

	obj := TokenObject{
		EncryptedToken: b64,
		KMSKeyID:       "key-1",
	}
	decoded, err := DecodeToken(&obj, "kms")
	if err != nil {
		t.Fatalf("DecodeToken kms: %v", err)
	}
	if !bytes.Equal(decoded.EncryptedToken, ciphertext) {
		t.Errorf("EncryptedToken = %q, want %q", decoded.EncryptedToken, ciphertext)
	}
	if decoded.KMSKeyID != "key-1" {
		t.Errorf("KMSKeyID = %q, want %q", decoded.KMSKeyID, "key-1")
	}
	if decoded.Passthrough {
		t.Error("Passthrough should be false in kms mode")
	}
}

func TestDecodeToken_KMSMissingEncToken(t *testing.T) {
	obj := TokenObject{Plaintext: "plain"}
	_, err := DecodeToken(&obj, "kms")
	if err == nil {
		t.Fatal("DecodeToken should fail when enc_token is missing in kms mode")
	}
}

func TestDecodeToken_KMSInvalidBase64(t *testing.T) {
	obj := TokenObject{
		EncryptedToken: "not-valid-base64!!!",
		KMSKeyID:       "key-1",
	}
	_, err := DecodeToken(&obj, "kms")
	if err == nil {
		t.Fatal("DecodeToken should fail on invalid base64")
	}
}

func TestDecodeToken_UnknownMode(t *testing.T) {
	obj := TokenObject{Plaintext: "x"}
	_, err := DecodeToken(&obj, "foobar")
	if err == nil {
		t.Fatal("DecodeToken should fail on unknown mode")
	}
}

func TestEncodeToken_Passthrough(t *testing.T) {
	obj, err := EncodeToken([]byte("Bearer token"), "", "passthrough")
	if err != nil {
		t.Fatalf("EncodeToken passthrough: %v", err)
	}
	if obj.Plaintext != "Bearer token" {
		t.Errorf("Plaintext = %q, want %q", obj.Plaintext, "Bearer token")
	}
	if obj.EncryptedToken != "" {
		t.Error("EncryptedToken should be empty in passthrough mode")
	}
}

func TestEncodeToken_KMS(t *testing.T) {
	raw := []byte("encrypted-data")
	obj, err := EncodeToken(raw, "key-2", "kms")
	if err != nil {
		t.Fatalf("EncodeToken kms: %v", err)
	}
	if obj.KMSKeyID != "key-2" {
		t.Errorf("KMSKeyID = %q, want %q", obj.KMSKeyID, "key-2")
	}

	decoded, err := base64.StdEncoding.DecodeString(obj.EncryptedToken)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("decoded = %q, want %q", decoded, raw)
	}
}

func TestEncodeToken_UnknownMode(t *testing.T) {
	_, err := EncodeToken([]byte("x"), "", "unknown")
	if err == nil {
		t.Fatal("EncodeToken should fail on unknown mode")
	}
}

func TestEncodeDecodeRoundtrip_KMS(t *testing.T) {
	raw := []byte("secret-ciphertext-bytes")
	obj, err := EncodeToken(raw, "key-rt", "kms")
	if err != nil {
		t.Fatalf("EncodeToken: %v", err)
	}

	decoded, err := DecodeToken(&obj, "kms")
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}

	if !bytes.Equal(decoded.EncryptedToken, raw) {
		t.Errorf("roundtrip: got %q, want %q", decoded.EncryptedToken, raw)
	}
	if decoded.KMSKeyID != "key-rt" {
		t.Errorf("roundtrip KMSKeyID: got %q, want %q", decoded.KMSKeyID, "key-rt")
	}
}

func TestEncodeDecodeRoundtrip_Passthrough(t *testing.T) {
	raw := []byte("Bearer plaintext-token")
	obj, err := EncodeToken(raw, "", "passthrough")
	if err != nil {
		t.Fatalf("EncodeToken: %v", err)
	}

	decoded, err := DecodeToken(&obj, "passthrough")
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}

	if decoded.Plaintext != string(raw) {
		t.Errorf("roundtrip: got %q, want %q", decoded.Plaintext, raw)
	}
}
