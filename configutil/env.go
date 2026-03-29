package configutil

import (
	"encoding"
	"os"
	"reflect"
	"strings"
)

// SafeExpandEnv expands ${VAR} and $VAR references to environment variables,
// but preserves bare numeric references ($1, $2, ${1}, etc.) which are regex
// back-references in path_rewrite rules.
//
// Supports bash-style defaults: ${VAR:-default} returns "default" when VAR
// is unset or empty, and ${VAR-default} returns "default" only when unset.
//
// POSIX environment variable names never start with a digit, so any variable
// reference whose name begins with 0-9 is a back-reference, not an env var.
func SafeExpandEnv(s string) string {
	return os.Expand(s, func(key string) string {
		if len(key) == 0 {
			return ""
		}
		if key[0] >= '0' && key[0] <= '9' {
			return "$" + key
		}

		if idx := strings.Index(key, ":-"); idx >= 0 {
			name := key[:idx]
			fallback := key[idx+2:]
			if val := os.Getenv(name); val != "" {
				return val
			}
			return fallback
		}
		if idx := strings.Index(key, "-"); idx >= 0 {
			name := key[:idx]
			fallback := key[idx+1:]
			if _, ok := os.LookupEnv(name); ok {
				return os.Getenv(name)
			}
			return fallback
		}

		return os.Getenv(key)
	})
}

// EnvExpandable is an optional interface for types whose MarshalText
// intentionally redacts the value (e.g. secret.Secret). Implementing
// this interface allows ExpandEnvInStruct to access the plaintext for
// env-var expansion without going through the redacting MarshalText path.
type EnvExpandable interface {
	ExpandableValue() string
	SetExpandedValue(string)
}

// ExpandEnvInStruct recursively walks a struct value and expands environment
// variable references (${VAR}, $VAR) in all string fields.
//
// This is YAML-injection-safe: expansion happens after YAML unmarshaling, so
// an env var value containing YAML control characters (quotes, newlines,
// colons) cannot alter the parsed configuration structure.
//
// Supported types:
//   - string fields: expanded directly via SafeExpandEnv.
//   - Types implementing EnvExpandable: expanded via plaintext accessor.
//   - Types implementing encoding.TextMarshaler + encoding.TextUnmarshaler:
//     expanded through those interfaces.
//   - map[K]V: values are recursively expanded (keys are left as-is).
//   - []T: elements are recursively expanded.
//   - Nested structs and pointers: recursed into.
//   - Non-string primitives (bool, int, float, etc.): skipped.
func ExpandEnvInStruct(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			ExpandEnvInStruct(v.Elem())
		}

	case reflect.Struct:
		if v.CanAddr() {
			ptr := v.Addr().Interface()
			if ex, ok := ptr.(EnvExpandable); ok {
				raw := ex.ExpandableValue()
				if expanded := SafeExpandEnv(raw); expanded != raw {
					ex.SetExpandedValue(expanded)
				}
				return
			}
			tm, isTM := ptr.(encoding.TextMarshaler)
			tu, isTU := ptr.(encoding.TextUnmarshaler)
			if isTM && isTU {
				text, err := tm.MarshalText()
				if err == nil && len(text) > 0 {
					expanded := SafeExpandEnv(string(text))
					if expanded != string(text) {
						_ = tu.UnmarshalText([]byte(expanded))
					}
				}
				return
			}
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			if f.CanSet() {
				ExpandEnvInStruct(f)
			}
		}

	case reflect.String:
		if v.CanSet() {
			expanded := SafeExpandEnv(v.String())
			if expanded != v.String() {
				v.SetString(expanded)
			}
		}

	case reflect.Map:
		if v.IsNil() {
			return
		}
		keys := v.MapKeys()
		for _, key := range keys {
			origVal := v.MapIndex(key)
			cp := reflect.New(origVal.Type()).Elem()
			cp.Set(origVal)
			ExpandEnvInStruct(cp)
			v.SetMapIndex(key, cp)
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			ExpandEnvInStruct(v.Index(i))
		}
	}
}
