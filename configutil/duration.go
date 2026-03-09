// Package configutil provides shared configuration primitives used across
// CSAR services: YAML-friendly Duration, safe environment variable expansion,
// and recursive struct expansion.
package configutil

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that supports YAML string unmarshalling (e.g. "30s").
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a duration string like "30s", "5m", "1h".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.String(), nil
}

// Std returns the underlying time.Duration. This is provided for compatibility
// with code that was using the newtype Duration pattern (e.g. csar-authn).
func (d Duration) Std() time.Duration {
	return d.Duration
}
