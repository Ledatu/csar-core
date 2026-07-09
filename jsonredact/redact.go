// Package jsonredact provides JSON field and key redaction utilities shared
// across CSAR services (DLP response masking, router audit capture, etc.).
package jsonredact

import (
	"encoding/json"
	"strings"

	"github.com/ledatu/csar-core/logutil"
)

// DefaultMask is the replacement string when none is configured.
const DefaultMask = "[REDACTED]"

// Config controls JSON parsing and redaction.
type Config struct {
	PathFields      []string
	SensitiveKeys   []string
	Mask            string
}

// ParseAndRedactJSON parses raw JSON and applies path + sensitive-key redaction.
func ParseAndRedactJSON(raw []byte, cfg Config) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	mask := cfg.Mask
	if mask == "" {
		mask = DefaultMask
	}

	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}

	paths := make([][]string, len(cfg.PathFields))
	for i, f := range cfg.PathFields {
		paths[i] = strings.Split(f, ".")
	}
	for _, path := range paths {
		RedactPath(data, path, mask)
	}
	if len(cfg.SensitiveKeys) > 0 {
		RedactKeys(data, cfg.SensitiveKeys, mask)
	} else {
		RedactSensitiveKeys(data, mask)
	}

	out, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

// RedactPath walks data along path and replaces the terminal field with mask.
// Returns true if anything was redacted.
func RedactPath(data any, path []string, mask string) bool {
	if len(path) == 0 {
		return false
	}

	switch v := data.(type) {
	case map[string]any:
		if len(path) == 1 {
			if _, ok := v[path[0]]; ok {
				v[path[0]] = mask
				return true
			}
			return false
		}

		key := path[0]
		if key == "*" {
			matched := false
			for k := range v {
				if RedactPath(v[k], path[1:], mask) {
					matched = true
				}
			}
			return matched
		}

		child, ok := v[key]
		if !ok {
			return false
		}
		return RedactPath(child, path[1:], mask)

	case []any:
		matched := false
		nextPath := path
		if path[0] == "*" {
			nextPath = path[1:]
		}
		for i := range v {
			if RedactPath(v[i], nextPath, mask) {
				matched = true
			}
		}
		return matched

	default:
		return false
	}
}

// RedactKeys redacts map keys matching keys list (case-insensitive) at any depth.
func RedactKeys(data any, keys []string, mask string) bool {
	if len(keys) == 0 {
		return false
	}

	lookup := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		lookup[strings.ToLower(k)] = struct{}{}
	}

	return redactKeysWalk(data, lookup, mask)
}

func redactKeysWalk(data any, keys map[string]struct{}, mask string) bool {
	switch v := data.(type) {
	case map[string]any:
		matched := false
		for k := range v {
			if _, ok := keys[strings.ToLower(k)]; ok {
				v[k] = mask
				matched = true
			} else if redactKeysWalk(v[k], keys, mask) {
				matched = true
			}
		}
		return matched
	case []any:
		matched := false
		for i := range v {
			if redactKeysWalk(v[i], keys, mask) {
				matched = true
			}
		}
		return matched
	default:
		return false
	}
}

// RedactSensitiveKeys redacts keys matching logutil sensitive patterns at any depth.
func RedactSensitiveKeys(data any, mask string) bool {
	switch v := data.(type) {
	case map[string]any:
		matched := false
		for k := range v {
			if logutil.IsSensitiveKey(k) {
				v[k] = mask
				matched = true
			} else if RedactSensitiveKeys(v[k], mask) {
				matched = true
			}
		}
		return matched
	case []any:
		matched := false
		for i := range v {
			if RedactSensitiveKeys(v[i], mask) {
				matched = true
			}
		}
		return matched
	default:
		return false
	}
}

// RedactQueryMap redacts query keys matching sensitive patterns and extraKeys (case-insensitive).
func RedactQueryMap(query map[string]string, mask string, extraKeys ...string) {
	lookup := make(map[string]struct{}, len(extraKeys))
	for _, k := range extraKeys {
		lookup[strings.ToLower(k)] = struct{}{}
	}
	for k := range query {
		if logutil.IsSensitiveKey(k) {
			query[k] = mask
			continue
		}
		if _, ok := lookup[strings.ToLower(k)]; ok {
			query[k] = mask
		}
	}
}
