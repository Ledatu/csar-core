package configsource

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashPolicy defines the integrity checking strategy for configs.
type HashPolicy int

const (
	// HashDisabled skips hash validation entirely.
	HashDisabled HashPolicy = iota

	// HashTOFU (Trust On First Use) records the hash on first fetch and
	// detects unexpected content changes when the ETag stays the same.
	HashTOFU

	// HashPinned validates every fetch against an operator-provided
	// SHA-256 hash. Any mismatch is rejected.
	HashPinned
)

// ComputeSHA256 returns the hex-encoded SHA-256 digest of data.
func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ValidateHash checks the current hash against the selected policy.
func ValidateHash(policy HashPolicy, pinnedHash, currentHash, lastHash, currentETag, lastETag string) error {
	switch policy {
	case HashDisabled:
		return nil

	case HashTOFU:
		if lastHash == "" {
			return nil
		}
		if currentETag == lastETag && currentHash != lastHash {
			return fmt.Errorf("config integrity violation: ETag unchanged (%s) but SHA-256 changed (%s → %s); possible tampering",
				currentETag, lastHash, currentHash)
		}
		return nil

	case HashPinned:
		if currentHash != pinnedHash {
			return fmt.Errorf("config SHA-256 mismatch: expected %s, got %s", pinnedHash, currentHash)
		}
		return nil

	default:
		return fmt.Errorf("unknown hash policy: %d", policy)
	}
}
