package httpmiddleware

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSConfig configures the CORS middleware.
type CORSConfig struct {
	AllowedOrigins   []string // e.g. ["https://example.com"], or ["*"] for any
	AllowedMethods   []string // e.g. ["GET", "POST", "PUT", "DELETE"]
	AllowedHeaders   []string // e.g. ["Authorization", "Content-Type"]
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int // preflight cache duration in seconds
}

// CORS returns middleware that handles Cross-Origin Resource Sharing.
// It responds to preflight OPTIONS requests and sets the appropriate
// headers on all responses.
func CORS(cfg *CORSConfig) Middleware {
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}
	}
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = []string{"Authorization", "Content-Type", "Accept", "X-Request-ID"}
	}

	allowAll := false
	originSet := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = struct{}{}
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	exposed := strings.Join(dedupHeaders(cfg.ExposedHeaders), ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed := allowAll
			if !allowed {
				_, allowed = originSet[origin]
			}

			if !allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Per the CORS spec, Access-Control-Allow-Origin: "*" must not
			// be used together with Access-Control-Allow-Credentials: true.
			if allowAll && !cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if exposed != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposed)
			}

			// Preflight.
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				if cfg.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", maxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// dedupHeaders returns headers with duplicate names removed
// (case-insensitive). The first occurrence wins.
func dedupHeaders(headers []string) []string {
	seen := make(map[string]bool, len(headers))
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		key := strings.ToLower(h)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}
