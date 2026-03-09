// Package secret provides a self-redacting string type for sensitive values
// (tokens, passwords, API keys) that is safe for structured logging.
package secret

import "log/slog"

const redactedValue = "[REDACTED]"

// Secret holds a sensitive string value (token, password, API key, etc.)
// that redacts itself when logged via slog. This provides compile-time
// defense-in-depth: even if a RedactingHandler is not installed, any
// slog output will print "[REDACTED]" instead of the plaintext.
//
// Usage:
//
//	type Config struct {
//	    IAMToken secret.Secret `yaml:"iam_token"`
//	}
//	logger.Info("config loaded", "iam_token", cfg.IAMToken) // → "[REDACTED]"
//	actual := cfg.IAMToken.Plaintext()                       // → real value
type Secret struct {
	value string
}

// NewSecret wraps a plaintext string in a Secret.
func NewSecret(plaintext string) Secret {
	return Secret{value: plaintext}
}

// Plaintext returns the underlying secret value.
// Use this only when you actually need the credential (e.g., for an HTTP header).
func (s Secret) Plaintext() string {
	return s.value
}

// String implements fmt.Stringer — always returns the redacted placeholder.
// This prevents accidental exposure via fmt.Println, %s, %v, etc.
func (s Secret) String() string {
	return redactedValue
}

// GoString implements fmt.GoStringer — prevents exposure via %#v.
func (s Secret) GoString() string {
	return "secret.Secret{" + redactedValue + "}"
}

// LogValue implements slog.LogValuer — the core defense mechanism.
// Any slog handler will call this instead of serializing the raw value.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedValue)
}

// IsEmpty returns true if the underlying secret is an empty string.
func (s Secret) IsEmpty() bool {
	return s.value == ""
}

// MarshalText implements encoding.TextMarshaler. Returns [REDACTED] to
// prevent accidental secret exposure through JSON/YAML/text serialization.
// Use Plaintext() when you need the actual value.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redactedValue), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for YAML/JSON unmarshal.
func (s *Secret) UnmarshalText(text []byte) error {
	s.value = string(text)
	return nil
}

// Compile-time interface checks.
var _ slog.LogValuer = Secret{}
