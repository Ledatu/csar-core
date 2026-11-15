// Package retryafter parses bounded HTTP Retry-After hints without owning retries.
package retryafter

import (
	"net/http"
	"strings"
	"time"
)

// MaxDelay bounds untrusted remote hints used by the shared HTTP clients.
const MaxDelay = 24 * time.Hour

// Parse accepts delta-seconds or an HTTP date. Invalid/past hints return zero;
// positive hints exceeding maximum are capped before duration arithmetic.
func Parse(raw string, now time.Time, maximum time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 128 || maximum <= 0 {
		return 0
	}
	digits := true
	for _, c := range raw {
		if c < '0' || c > '9' {
			digits = false
			break
		}
	}
	if digits {
		var seconds int64
		for _, c := range raw {
			seconds = seconds*10 + int64(c-'0')
			if seconds > int64(maximum/time.Second) {
				return maximum
			}
		}
		return time.Duration(seconds) * time.Second
	}
	at, err := http.ParseTime(raw)
	if err != nil || !at.After(now) {
		return 0
	}
	delay := at.Sub(now)
	if delay > maximum {
		return maximum
	}
	return delay
}
