// Package configutil provides shared configuration primitives used across
// CSAR services: YAML-friendly Duration, safe environment variable expansion,
// and recursive struct expansion.
package configutil

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	dayPattern     = regexp.MustCompile(`(\d+)d`)
	fracDayPattern = regexp.MustCompile(`\d*\.\d+d`)
)

// parseDuration extends time.ParseDuration with support for a "d" (day) suffix.
// Occurrences of "<N>d" are replaced with "<N*24>h" before delegating to the
// standard library, so "7d", "30d12h", and mixed forms all work.
// Fractional days (e.g. "1.5d") are rejected; use hours instead.
func parseDuration(s string) (time.Duration, error) {
	if fracDayPattern.MatchString(s) {
		return 0, fmt.Errorf("fractional days are not supported in %q; use hours instead (e.g. \"36h\" instead of \"1.5d\")", s)
	}
	expanded := dayPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := dayPattern.FindStringSubmatch(m)
		n, _ := strconv.Atoi(sub[1])
		return strconv.Itoa(n*24) + "h"
	})
	return time.ParseDuration(expanded)
}

// Duration is a time.Duration that supports YAML string unmarshalling (e.g. "30s").
// In addition to the standard Go duration units, the "d" (day = 24h) suffix is
// supported: "7d", "30d", "1d12h" all parse correctly.
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a duration string like "30s", "5m", "1h", "7d".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := parseDuration(s)
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
