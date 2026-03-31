package grpcdial

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ledatu/csar-core/tlsx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config describes how to establish a gRPC client connection.
type Config struct {
	Address        string
	Insecure       bool
	RequireCA      bool // reject if !Insecure && CAFile==""
	CAFile         string
	CertFile       string
	KeyFile        string
	DefaultTimeout time.Duration
	TokenSource    credentials.PerRPCCredentials
}

// Dial establishes a gRPC client connection with consistent TLS handling.
func Dial(cfg *Config, logger *slog.Logger) (*grpc.ClientConn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("grpcdial: config is required")
	}
	if cfg.Address == "" {
		return nil, fmt.Errorf("grpcdial: address is required")
	}

	var opts []grpc.DialOption

	if cfg.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		if cfg.RequireCA && cfg.CAFile == "" {
			return nil, fmt.Errorf("grpcdial: ca_file is required when require_ca is set (address: %s)", cfg.Address)
		}
		tc, err := tlsx.NewClientTLSConfig(tlsx.ClientConfig{
			CAFile:   cfg.CAFile,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		})
		if err != nil {
			return nil, fmt.Errorf("grpcdial: building TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	}

	if cfg.TokenSource != nil {
		opts = append(opts, grpc.WithPerRPCCredentials(cfg.TokenSource))
	}

	if cfg.DefaultTimeout > 0 {
		opts = append(opts, grpc.WithUnaryInterceptor(timeoutInterceptor(cfg.DefaultTimeout)))
	}

	conn, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpcdial: dial %s: %w", cfg.Address, err)
	}

	logger.Info("grpcdial: connected", "address", cfg.Address, "insecure", cfg.Insecure)
	return conn, nil
}

func timeoutInterceptor(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
