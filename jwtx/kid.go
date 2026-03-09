// Package jwtx provides shared JWT signing, verification, JWKS generation,
// and key ID derivation for the CSAR platform.
package jwtx

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// ComputeKID derives a key ID from the SHA-256 hash of DER-encoded public key bytes.
// Returns the first 8 bytes as a 16-character hex string.
func ComputeKID(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return hex.EncodeToString(h[:8])
}

// ComputeKIDFromPublicKey marshals a crypto.PublicKey to PKIX DER form and
// derives its KID via ComputeKID.
func ComputeKIDFromPublicKey(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("jwtx: marshal public key: %w", err)
	}
	return ComputeKID(der), nil
}
