// Package grpcserver provides lifecycle helpers for gRPC servers.
package grpcserver

import (
	"context"

	"google.golang.org/grpc"
)

// Shutdown stops accepting new RPCs and waits for existing RPCs to finish.
// The caller must supply a bounded context and drain long-lived subscriptions
// separately. If the context expires, remaining transports are forcibly closed
// and the context error is returned. Handlers that ignore cancellation may
// outlive this call; their resources must remain safe until process exit.
func Shutdown(ctx context.Context, server *grpc.Server) error {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		server.Stop()
		return ctx.Err()
	}
}
