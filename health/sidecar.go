package health

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-core/httpserver"
)

// SidecarConfig configures a plain HTTP health/readiness/metrics sidecar for
// orchestrator probes (avoids TCP checks against mTLS listeners).
type SidecarConfig struct {
	// Addr is the listen address (e.g. "127.0.0.1:9082"). Required.
	// Bind to loopback when the orchestrator probes from inside the same
	// network namespace to avoid exposing unauthenticated probe endpoints.
	Addr string
	// Version is reported by the liveness probe (e.g. service name or release).
	Version string
	// Readiness, if non-nil, is served at /readiness.
	Readiness *ReadinessChecker
	// Metrics, if non-nil, is served at /metrics.
	Metrics http.Handler
	// Logger receives server lifecycle events; if nil, slog.Default() is used.
	Logger *slog.Logger
}

// Sidecar is a plain HTTP server exposing /health and optional /readiness and /metrics.
type Sidecar struct {
	srv *httpserver.Server
}

// NewSidecar builds a sidecar HTTP server. TLS is disabled (plain HTTP).
func NewSidecar(cfg SidecarConfig) (*Sidecar, error) {
	if strings.TrimSpace(cfg.Addr) == "" {
		return nil, fmt.Errorf("health: SidecarConfig.Addr is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.Handle("/health", Handler(cfg.Version))
	if cfg.Readiness != nil {
		mux.Handle("/readiness", cfg.Readiness.Handler())
	}
	if cfg.Metrics != nil {
		mux.Handle("/metrics", cfg.Metrics)
	}

	srv, err := httpserver.New(&httpserver.Config{
		Addr:         cfg.Addr,
		Handler:      mux,
		TLS:          nil,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, logger.With("component", "health_sidecar"))
	if err != nil {
		return nil, fmt.Errorf("health: sidecar server: %w", err)
	}

	return &Sidecar{srv: srv}, nil
}

// ListenAndServe starts the plain HTTP server; it blocks until the server stops.
func (s *Sidecar) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

// Shutdown gracefully drains the sidecar.
func (s *Sidecar) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
