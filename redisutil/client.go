package redisutil

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// NewClient creates a go-redis client from the provided config.
func NewClient(ctx context.Context, cfg Config) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}

	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping %s: %w", cfg.Addr, err)
	}
	return client, nil
}
