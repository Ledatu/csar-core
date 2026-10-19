// Package httpserver provides a standard HTTP server with sane defaults,
// optional TLS/mTLS via tlsx, and graceful shutdown on OS signals.
package httpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ledatu/csar-core/tlsx"
)

// Config describes how to build and run the HTTP server.
type Config struct {
	Addr            string             // listen address (e.g. ":8080")
	Handler         http.Handler       // root handler / mux
	TLS             *tlsx.ServerConfig // nil = plain HTTP
	ReadTimeout     time.Duration      // default 30s
	WriteTimeout    time.Duration      // default 60s
	IdleTimeout     time.Duration      // default 120s
	MaxHeaderBytes  int                // default 1 MB
	ShutdownTimeout time.Duration      // default 30s
}

// Server wraps an http.Server with lifecycle helpers.
type Server struct {
	srv             *http.Server
	tlsCfg          *tlsx.ServerConfig
	shutdownTimeout time.Duration
	logger          *slog.Logger
	state           atomic.Uint32
}

const (
	stateIdle uint32 = iota
	stateStarting
	stateServing
	stateDraining
	stateStopped
)

// New creates a Server. It builds the TLS config eagerly (if configured)
// so cert errors are caught before the first request.
func New(cfg *Config, logger *slog.Logger) (*Server, error) {
	applyDefaults(cfg)

	srv := &http.Server{
		Addr:           cfg.Addr,
		Handler:        cfg.Handler,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxHeaderBytes: cfg.MaxHeaderBytes,
	}

	if cfg.TLS != nil {
		tc, err := tlsx.NewServerTLSConfig(*cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("httpserver: TLS config: %w", err)
		}
		srv.TLSConfig = tc
	}

	return &Server{
		srv:             srv,
		tlsCfg:          cfg.TLS,
		shutdownTimeout: cfg.ShutdownTimeout,
		logger:          logger,
	}, nil
}

// ListenAndServe starts the server. It blocks until the server is closed.
// When TLS is configured, the certificates are already loaded into the
// tls.Config by New, so no file paths are needed here.
func (s *Server) ListenAndServe() error {
	if !s.state.CompareAndSwap(stateIdle, stateStarting) {
		return http.ErrServerClosed
	}
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		s.state.Store(stateStopped)
		return err
	}
	return s.serve(ln)
}

// Serve serves an already-bound listener and closes it on return. A Server is
// single-use, including after a failed bind or a shutdown before startup.
func (s *Server) Serve(ln net.Listener) error {
	if !s.state.CompareAndSwap(stateIdle, stateStarting) {
		_ = ln.Close()
		return http.ErrServerClosed
	}
	return s.serve(ln)
}

func (s *Server) serve(ln net.Listener) error {
	defer s.state.Store(stateStopped)
	tracked := &servingListener{Listener: ln, state: &s.state}
	if s.tlsCfg != nil {
		s.logger.Info("starting HTTPS server", "addr", s.srv.Addr)
		return s.srv.ServeTLS(tracked, "", "")
	}
	s.logger.Info("starting HTTP server", "addr", s.srv.Addr)
	return s.srv.Serve(tracked)
}

// IsServing reports listener lifecycle only, without making a connection to
// the application. It does not validate TLS or an end-to-end HTTP response.
func (s *Server) IsServing() bool {
	return s.state.Load() == stateServing
}

type servingListener struct {
	net.Listener
	state *atomic.Uint32
}

func (ln *servingListener) Accept() (net.Conn, error) {
	// Serve has registered the listener and reached its accept loop. A shutdown
	// racing with the first Accept must never make the server ready again.
	ln.state.CompareAndSwap(stateStarting, stateServing)
	return ln.Listener.Accept()
}

// Shutdown gracefully drains connections. The provided context controls
// the deadline; if nil, the configured ShutdownTimeout is used.
func (s *Server) Shutdown(ctx context.Context) error {
	s.state.Store(stateDraining)
	s.logger.Info("shutting down server")
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()
	}
	return s.srv.Shutdown(ctx)
}

// TLSConfig returns the resolved tls.Config, or nil for a plain HTTP server.
func (s *Server) TLSConfig() *tls.Config {
	return s.srv.TLSConfig
}

// Run starts the server and blocks until SIGINT or SIGTERM is received,
// then performs graceful shutdown. This is a convenience for simple
// main() functions.
func (s *Server) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutdown signal received, draining connections")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	s.logger.Info("server stopped gracefully")
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 60 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = 1 << 20 // 1 MB
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
}
