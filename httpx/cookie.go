// Package httpx provides small reusable HTTP helpers shared across CSAR services.
package httpx

import (
	"net/http"
	"strings"
)

// ParseSameSite converts a string ("strict", "none", "lax") to http.SameSite.
// Defaults to SameSiteLaxMode for unrecognized values.
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
