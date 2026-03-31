// Package authzclient provides a typed gRPC client for connecting
// to csar-authz via grpcdial with optional PerRPC auth.
package authzclient

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/ledatu/csar-core/grpcdial"
	pb "github.com/ledatu/csar-proto/csar/authz/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Config struct {
	Address        string
	Insecure       bool
	CAFile         string
	CertFile       string
	KeyFile        string
	TokenSource    credentials.PerRPCCredentials
	DefaultTimeout time.Duration
}

func Dial(cfg *Config, logger *slog.Logger) (*grpc.ClientConn, pb.AuthzServiceClient, error) {
	conn, err := grpcdial.Dial(&grpcdial.Config{
		Address:        cfg.Address,
		Insecure:       cfg.Insecure,
		CAFile:         cfg.CAFile,
		CertFile:       cfg.CertFile,
		KeyFile:        cfg.KeyFile,
		DefaultTimeout: cfg.DefaultTimeout,
		TokenSource:    cfg.TokenSource,
	}, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("authzclient: %w", err)
	}

	return conn, pb.NewAuthzServiceClient(conn), nil
}
