package s3store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// TokenObject is the JSON structure stored in each S3 object.
//
// Two formats are supported:
//
// Passthrough (S3-only, SSE handles encryption at rest):
//
//	{"plaintext": "Bearer sk-xxxxx"}
//
// KMS (pre-encrypted with CSAR KMS):
//
//	{"enc_token": "base64-ciphertext", "kms_key_id": "abj-xxx"}
type TokenObject struct {
	// EncryptedToken is the base64-encoded ciphertext (KMS mode).
	EncryptedToken string `json:"enc_token,omitempty"`

	// KMSKeyID is the KMS key used for encryption (KMS mode).
	KMSKeyID string `json:"kms_key_id,omitempty"`

	// Plaintext is the raw token value (passthrough mode).
	Plaintext string `json:"plaintext,omitempty"`

	// Metadata fields (optional, written by admin API).
	UpdatedAt     string `json:"updated_at,omitempty"`
	UpdatedBy     string `json:"updated_by,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
}

// ParseTokenObject parses an S3 object body into a TokenObject.
// Returns an error if the JSON is invalid or if neither plaintext
// nor enc_token is present.
func ParseTokenObject(data []byte) (TokenObject, error) {
	var obj TokenObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return TokenObject{}, fmt.Errorf("s3store: parse token object: %w", err)
	}

	if obj.Plaintext == "" && obj.EncryptedToken == "" {
		return TokenObject{}, fmt.Errorf("s3store: token object must have either \"plaintext\" or \"enc_token\" field")
	}

	if obj.EncryptedToken != "" && obj.KMSKeyID == "" {
		return TokenObject{}, fmt.Errorf("s3store: token object with \"enc_token\" requires \"kms_key_id\"")
	}

	return obj, nil
}

// MarshalTokenObject serializes a TokenObject to JSON suitable for S3 storage.
func MarshalTokenObject(obj *TokenObject) ([]byte, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("s3store: marshal token object: %w", err)
	}
	return data, nil
}

// DecodedToken is the result of decoding a TokenObject with a given KMS mode.
type DecodedToken struct {
	// Plaintext is the raw token value (passthrough mode only).
	Plaintext string

	// EncryptedToken is the raw ciphertext bytes after base64 decoding (kms mode only).
	EncryptedToken []byte

	// KMSKeyID is the KMS key used for encryption (kms mode only).
	KMSKeyID string

	// Passthrough is true when the token was stored in passthrough (SSE) mode.
	Passthrough bool
}

// DecodeToken interprets a TokenObject according to the given kmsMode.
//
// In "passthrough" mode, obj.Plaintext is returned directly.
// In "kms" mode, obj.EncryptedToken is base64-decoded and returned along with
// the KMS key ID.
func DecodeToken(obj *TokenObject, kmsMode string) (DecodedToken, error) {
	switch kmsMode {
	case "passthrough":
		if obj.Plaintext == "" {
			return DecodedToken{}, fmt.Errorf("s3store: passthrough mode requires \"plaintext\" field")
		}
		return DecodedToken{
			Plaintext:   obj.Plaintext,
			Passthrough: true,
		}, nil

	case "kms":
		if obj.EncryptedToken == "" {
			return DecodedToken{}, fmt.Errorf("s3store: kms mode requires \"enc_token\" field")
		}
		decoded, err := base64.StdEncoding.DecodeString(obj.EncryptedToken)
		if err != nil {
			return DecodedToken{}, fmt.Errorf("s3store: invalid base64 in enc_token: %w", err)
		}
		return DecodedToken{
			EncryptedToken: decoded,
			KMSKeyID:       obj.KMSKeyID,
		}, nil

	default:
		return DecodedToken{}, fmt.Errorf("s3store: unknown kms_mode %q", kmsMode)
	}
}

// EncodeToken builds a TokenObject from raw token data for the given kmsMode.
//
// In "passthrough" mode, the raw bytes are stored as a plaintext string.
// In "kms" mode, the raw bytes are base64-encoded into EncryptedToken and the
// KMS key ID is recorded.
func EncodeToken(raw []byte, kmsKeyID string, kmsMode string) (TokenObject, error) {
	switch kmsMode {
	case "passthrough":
		return TokenObject{
			Plaintext: string(raw),
		}, nil

	case "kms":
		return TokenObject{
			EncryptedToken: base64.StdEncoding.EncodeToString(raw),
			KMSKeyID:       kmsKeyID,
		}, nil

	default:
		return TokenObject{}, fmt.Errorf("s3store: unknown kms_mode %q", kmsMode)
	}
}
