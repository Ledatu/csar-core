package httpx

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// OptionalBool parses an optional boolean query-parameter value. An empty or
// all-whitespace string yields (nil, nil); a parse failure is returned to the
// caller unchanged.
func OptionalBool(raw string) (*bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// Truthy returns true when raw parses as a truthy boolean per strconv.ParseBool
// after trimming whitespace. All other inputs (including empty or invalid) are
// treated as false.
func Truthy(raw string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && parsed
}

// Values flattens comma-separated query-parameter repeats into a single slice,
// trimming whitespace and dropping empty entries.
func Values(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// ParseInt64List parses a slice of strings as strictly positive int64 values.
// An empty input yields an empty slice. A non-numeric entry returns the
// underlying strconv error; non-positive entries return a stable message.
func ParseInt64List(raw []string) ([]int64, error) {
	out := make([]int64, 0, len(raw))
	for _, item := range raw {
		parsed, err := strconv.ParseInt(item, 10, 64)
		if err != nil {
			return nil, err
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("nm_id must be positive")
		}
		out = append(out, parsed)
	}
	return out, nil
}

// ParseLimit extracts the "limit" query parameter. Empty or non-positive
// values fall back to def. Values above max are clamped to max along with a
// descriptive error so callers may either honour the clamp or surface a
// validation error.
func ParseLimit(r *http.Request, def, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return def, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return def, nil
	}
	if parsed > max {
		return max, fmt.Errorf("limit exceeds maximum of %d", max)
	}
	return parsed, nil
}
