// Package authzclient provides a shared gRPC dial helper for connecting
// to csar-authz with consistent TLS and optional PerRPC auth.
package authzclient

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ledatu/csar-core/tlsx"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config describes how to connect to csar-authz.
type Config struct {
	Address        string                        // gRPC endpoint (host:port)
	Insecure       bool                          // use plaintext instead of TLS
	CAFile         string                        // PEM CA for server verification
	CertFile       string                        // PEM client cert for mTLS
	KeyFile        string                        // PEM client key for mTLS
	TokenSource    credentials.PerRPCCredentials // optional service JWT (e.g. grpcjwt.ServiceTokenSource)
	DefaultTimeout time.Duration                 // per-call timeout; 0 means no default
}

// Dial establishes a gRPC connection and returns both the raw connection
// (for lifecycle management) and a typed AuthzServiceClient.
func Dial(cfg *Config, logger *slog.Logger) (*grpc.ClientConn, pb.AuthzServiceClient, error) {
	var opts []grpc.DialOption

	if cfg.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tc, err := tlsx.NewClientTLSConfig(tlsx.ClientConfig{
			CAFile:   cfg.CAFile,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("authzclient: building TLS config: %w", err)
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
		return nil, nil, fmt.Errorf("authzclient: dial %s: %w", cfg.Address, err)
	}

	logger.Info("authzclient: connected", "address", cfg.Address, "insecure", cfg.Insecure)
	return conn, pb.NewAuthzServiceClient(conn), nil
}

func timeoutInterceptor(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
