package s3store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// CredentialFingerprint is a stable identity for high-entropy stored credential
// material, independent of encryption and object metadata. It is not a checksum
// of the S3 object or an authorization decision. Never log the input.
func CredentialFingerprint(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// ValidateStoredExpiry validates an optional owner-inspected expiry. Missing
// lifetime is unknown; a deadline in the past is valid metadata and fails closed
// when a reader attempts to use the credential.
func ValidateStoredExpiry(expiry *time.Time) error {
	if expiry != nil && (expiry.IsZero() || expiry.Year() < 1970 || expiry.Year() > 9999) {
		return fmt.Errorf("s3store: invalid stored credential expiry")
	}
	return nil
}
func normalizeStoredMetadata(obj *TokenObject) error {
	if err := ValidateStoredExpiry(obj.ExpiresAt); err != nil {
		return err
	}
	if obj.ExpiresAt != nil {
		if obj.IsDescriptor() {
			return fmt.Errorf("s3store: descriptor cannot carry stored expiry")
		}
		utc := obj.ExpiresAt.UTC()
		obj.ExpiresAt = &utc
	}
	if obj.CredentialID != "" {
		_, err := hex.DecodeString(obj.CredentialID)
		if err != nil || len(obj.CredentialID) != 64 || obj.IsDescriptor() {
			return fmt.Errorf("s3store: invalid stored credential identity")
		}
	}
	return nil
}
