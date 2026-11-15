package clientx

import (
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-core/httpx/retryafter"
)

func routerHints(h http.Header) (string, time.Duration) {
	status := strings.TrimSpace(h.Get("X-CSAR-Status"))
	switch status {
	case "throttled", "backpressure", "circuit_open", "circuit_half_open", "throttle_unavailable", "server_draining":
	case "":
		return "", 0
	default:
		status = "unknown"
	}
	raw := strings.TrimSpace(h.Get("X-CSAR-Wait-MS"))
	if raw == "" || len(raw) > 128 {
		return status, 0
	}
	var millis int64
	for _, c := range raw {
		if c < '0' || c > '9' {
			return status, 0
		}
		millis = millis*10 + int64(c-'0')
		if millis > int64(retryafter.MaxDelay/time.Millisecond) {
			return status, retryafter.MaxDelay
		}
	}
	return status, time.Duration(millis) * time.Millisecond
}
