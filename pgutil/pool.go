// Package pgutil provides shared PostgreSQL utilities for CSAR services.
//
// It wraps pgxpool for connection pool management, provides a migration runner,
// transaction helpers, and common error mapping.
package pgutil

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOption configures the connection pool.
type PoolOption func(*poolConfig)

type poolConfig struct {
	logger          *slog.Logger
	maxConns        int32
	minConns        int32
	maxConnLifetime time.Duration
}

// WithLogger sets the logger for pool operations.
func WithLogger(l *slog.Logger) PoolOption {
	return func(c *poolConfig) { c.logger = l }
}

// WithMaxConns sets the maximum number of connections in the pool.
func WithMaxConns(n int32) PoolOption {
	return func(c *poolConfig) { c.maxConns = n }
}

// WithMinConns sets the minimum number of idle connections in the pool.
func WithMinConns(n int32) PoolOption {
	return func(c *poolConfig) { c.minConns = n }
}

// WithMaxConnLifetime sets the maximum lifetime of a connection before it is closed and replaced.
func WithMaxConnLifetime(d time.Duration) PoolOption {
	return func(c *poolConfig) { c.maxConnLifetime = d }
}

// NewPool creates a new pgxpool.Pool from a DSN, applies options, and verifies connectivity.
func NewPool(ctx context.Context, dsn string, opts ...PoolOption) (*pgxpool.Pool, error) {
	cfg := &poolConfig{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}

	if cfg.maxConns > 0 {
		poolCfg.MaxConns = cfg.maxConns
	}
	if cfg.minConns > 0 {
		poolCfg.MinConns = cfg.minConns
	}
	if cfg.maxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.maxConnLifetime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	cfg.logger.Info("database pool connected", "host", poolCfg.ConnConfig.Host, "database", poolCfg.ConnConfig.Database)
	return pool, nil
}
