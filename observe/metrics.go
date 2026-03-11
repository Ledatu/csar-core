package observe

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsConfig controls Prometheus metrics setup.
type MetricsConfig struct {
	Enabled bool
}

// NewRegistry creates a fresh Prometheus registry. Using a non-default
// registry avoids polluting the global namespace with metrics from
// other libraries.
func NewRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}

// MetricsHandler returns an HTTP handler that exposes the given
// registry's metrics in Prometheus exposition format.
func MetricsHandler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}
