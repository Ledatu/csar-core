package grpcserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type observingListener struct {
	net.Listener
	once   sync.Once
	closed chan struct{}
}

func (l *observingListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

type blockingHealth struct {
	healthpb.UnimplementedHealthServer
	entered chan struct{}
	release chan struct{}
	exited  chan struct{}
}

func (h *blockingHealth) Check(ctx context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	close(h.entered)
	defer close(h.exited)
	select {
	case <-h.release:
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestShutdown(t *testing.T) {
	for _, forced := range []bool{false, true} {
		name := "drains_active_rpc"
		if forced {
			name = "cancels_active_rpc_at_deadline"
		}
		t.Run(name, func(t *testing.T) {
			srv := grpc.NewServer()
			t.Cleanup(srv.Stop)
			handler := &blockingHealth{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			healthpb.RegisterHealthServer(srv, handler)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			observed := &observingListener{Listener: listener, closed: make(chan struct{})}
			serveDone := make(chan error, 1)
			go func() { serveDone <- srv.Serve(observed) }()
			conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if closeErr := conn.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			})
			rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer rpcCancel()
			rpcDone := make(chan error, 1)
			go func() {
				_, callErr := healthpb.NewHealthClient(conn).Check(rpcCtx, &healthpb.HealthCheckRequest{})
				rpcDone <- callErr
			}()
			select {
			case <-handler.entered:
			case <-rpcCtx.Done():
				t.Fatal("RPC did not reach handler")
			}
			stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
			defer stopCancel()
			stopDone := make(chan error, 1)
			go func() { stopDone <- Shutdown(stopCtx, srv) }()
			if !forced {
				// Closing the listener proves graceful shutdown began while the
				// original RPC remains active; do not rely on a fixed sleep.
				select {
				case <-observed.closed:
				case <-rpcCtx.Done():
					t.Fatal("server did not stop accepting connections")
				}
				select {
				case err := <-stopDone:
					t.Fatalf("shutdown returned before active RPC completed: %v", err)
				default:
				}
				close(handler.release)
			}
			select {
			case err := <-stopDone:
				if forced && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("forced shutdown error = %v", err)
				}
				if !forced && err != nil {
					t.Fatal(err)
				}
			case <-rpcCtx.Done():
				t.Fatal("shutdown exceeded test deadline")
			}
			select {
			case err := <-rpcDone:
				if (err != nil) != forced {
					t.Fatalf("RPC error = %v, forced = %v", err, forced)
				}
			case <-rpcCtx.Done():
				t.Fatal("RPC did not settle")
			}
			select {
			case <-handler.exited:
			case <-rpcCtx.Done():
				t.Fatal("handler did not exit")
			}
			select {
			case serveErr := <-serveDone:
				if serveErr != nil {
					t.Fatal(serveErr)
				}
			case <-rpcCtx.Done():
				t.Fatal("server did not exit")
			}
		})
	}
}
